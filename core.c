// core.c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/sched/mm.h>
#include <linux/version.h>
#include <linux/pid.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/mount.h>
// 引入 Uprobes 头文件
#include <linux/uprobes.h>

#include "comm.h"

#define DEVICE_NAME "shami"

// --- 辅助函数：GUP 强力读取 ---
static int read_memory_force(struct mm_struct *mm, unsigned long addr, void *buffer, size_t size) {
    struct page *page;
    void *maddr;
    int res;
    size_t bytes_read = 0;
    
    while (bytes_read < size) {
        size_t offset = (addr + bytes_read) & ~PAGE_MASK;
        size_t bytes_to_copy = min(size - bytes_read, PAGE_SIZE - offset);

        res = get_user_pages_remote(mm, addr + bytes_read, 1, FOLL_FORCE, &page, NULL, NULL);
        if (res <= 0) return -1;

        maddr = kmap_atomic(page);
        memcpy(buffer + bytes_read, maddr + offset, bytes_to_copy);
        kunmap_atomic(maddr);
        
        put_page(page);
        bytes_read += bytes_to_copy;
    }
    return 0;
}

// --- 辅助函数：GUP 强力写入 ---
static int write_memory_force(struct mm_struct *mm, unsigned long addr, void *data, size_t size) {
    struct page *page;
    void *maddr;
    int res;
    size_t bytes_written = 0;

    while (bytes_written < size) {
        size_t offset = (addr + bytes_written) & ~PAGE_MASK;
        size_t bytes_to_copy = min(size - bytes_written, PAGE_SIZE - offset);

        res = get_user_pages_remote(mm, addr + bytes_written, 1, FOLL_WRITE | FOLL_FORCE, &page, NULL, NULL);
        if (res <= 0) return -1;

        maddr = kmap_atomic(page);
        memcpy(maddr + offset, data + bytes_written, bytes_to_copy);
        kunmap_atomic(maddr);
        
        set_page_dirty_lock(page);
        put_page(page);
        bytes_written += bytes_to_copy;
    }
    return 0;
}

// ---------------------------------------------------------
// --- Uprobes 相关功能 ---
// ---------------------------------------------------------

// 定义我们自己的 Uprobe 节点，用于链表管理
struct my_uprobe_ctx {
    struct list_head list;
    struct uprobe_consumer consumer;
    struct inode *inode;
    loff_t offset;
    unsigned long vaddr; // 记录原始虚拟地址方便查找
    pid_t pid;           // 记录PID
};

static LIST_HEAD(uprobe_list);
static DEFINE_MUTEX(uprobe_lock);

// 断点触发时的回调函数
// 注意：该函数在中断上下文中运行，不要执行休眠操作
// core.c 中修改这个函数
static int my_uprobe_handler(struct uprobe_consumer *con, struct pt_regs *regs) {
    struct my_uprobe_ctx *ctx = container_of(con, struct my_uprobe_ctx, consumer);
    
    // --- ARM64 适配修改 ---
    printk(KERN_INFO "[Shami] Uprobe HIT! PID: %d, VAddr: 0x%lx\n", ctx->pid, ctx->vaddr);
    // x86: regs->ip, regs->ax
    // ARM64: regs->pc (Program Counter), regs->regs[0] (也就是 x0 寄存器，通常是返回值或第一个参数)
    printk(KERN_INFO "[Shami] REGS - PC: 0x%llx, SP: 0x%llx, X0: 0x%llx\n", 
           regs->pc, regs->sp, regs->regs[0]);
    
    return 0;
}

// 辅助：根据 PID 和 虚拟地址 查找对应的 Inode 和 Offset
// Uprobes 必须注册在 (inode, offset) 上，而不是虚拟地址上
static int resolve_addr_to_inode_offset(pid_t pid, unsigned long vaddr, struct inode **out_inode, loff_t *out_offset) {
    struct task_struct *task;
    struct pid *pid_struct;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    struct file *vma_file;
    int ret = -EINVAL;

    pid_struct = find_get_pid(pid);
    if (!pid_struct) return -ESRCH;

    task = get_pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        put_pid(pid_struct);
        return -ESRCH;
    }

    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        put_pid(pid_struct);
        return -EINVAL;
    }

    // 必须要持有 mmap锁 才能遍历 vma
    mmap_read_lock(mm);
    
    vma = find_vma(mm, vaddr);
    if (vma && vma->vm_start <= vaddr && vma->vm_file) {
        vma_file = vma->vm_file;
        *out_inode = file_inode(vma_file);
        
        // 增加 inode 引用计数，防止文件被关闭后 inode 消失
        ihold(*out_inode);
        
        // 计算文件内的偏移量
        // Offset = (Addr - VMA_Start) + (VMA_Page_Offset << PAGE_SHIFT)
        *out_offset = (vaddr - vma->vm_start) + (vma->vm_pgoff << PAGE_SHIFT);
        ret = 0;
    } else {
        // 地址无效或该内存区域不是文件映射（如堆栈/堆）
        // Uprobes 只能用于文件映射的代码段
        ret = -EFAULT;
    }

    mmap_read_unlock(mm);
    mmput(mm);
    put_task_struct(task);
    put_pid(pid_struct);
    
    return ret;
}

static int add_uprobe(pid_t pid, unsigned long vaddr) {
    struct my_uprobe_ctx *ctx;
    struct inode *inode = NULL;
    loff_t offset = 0;
    int ret;

    // 1. 解析地址
    ret = resolve_addr_to_inode_offset(pid, vaddr, &inode, &offset);
    if (ret) return ret;

    // 2. 分配上下文
    ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
    if (!ctx) {
        iput(inode);
        return -ENOMEM;
    }

    // 3. 填充 consumer
    ctx->consumer.handler = my_uprobe_handler;
    ctx->inode = inode;
    ctx->offset = offset;
    ctx->vaddr = vaddr;
    ctx->pid = pid;

    // 4. 注册 Uprobe
    ret = uprobe_register(inode, offset, &ctx->consumer);
    if (ret) {
        printk(KERN_ERR "[Shami] uprobe_register failed: %d\n", ret);
        iput(inode);
        kfree(ctx);
        return ret;
    }

    // 5. 加入链表
    mutex_lock(&uprobe_lock);
    list_add(&ctx->list, &uprobe_list);
    mutex_unlock(&uprobe_lock);

    printk(KERN_INFO "[Shami] Uprobe added at PID %d, Addr 0x%lx (Inode %lu, Off 0x%llx)\n", 
           pid, vaddr, inode->i_ino, offset);
    
    return 0;
}

static int del_uprobe(pid_t pid, unsigned long vaddr) {
    struct my_uprobe_ctx *ctx, *tmp;
    int found = 0;

    mutex_lock(&uprobe_lock);
    list_for_each_entry_safe(ctx, tmp, &uprobe_list, list) {
        if (ctx->pid == pid && ctx->vaddr == vaddr) {
            uprobe_unregister(ctx->inode, ctx->offset, &ctx->consumer);
            iput(ctx->inode); // 释放 inode 引用
            list_del(&ctx->list);
            kfree(ctx);
            found = 1;
            break; // 假设同一地址只下一次
        }
    }
    mutex_unlock(&uprobe_lock);

    return found ? 0 : -ENOENT;
}

static void clean_all_uprobes(void) {
    struct my_uprobe_ctx *ctx, *tmp;
    
    mutex_lock(&uprobe_lock);
    list_for_each_entry_safe(ctx, tmp, &uprobe_list, list) {
        uprobe_unregister(ctx->inode, ctx->offset, &ctx->consumer);
        iput(ctx->inode);
        list_del(&ctx->list);
        kfree(ctx);
    }
    mutex_unlock(&uprobe_lock);
}

// ---------------------------------------------------------
// --- IOCTL 主处理函数 ---
// ---------------------------------------------------------
static long shami_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    struct task_struct *task;
    struct pid *pid_struct;
    struct mm_struct *mm;
    long ret = -EINVAL;
    COPY_MEMORY cm;
    UPROBE_CONFIG uc;
    void *kbuf = NULL;

    // 读写内存处理
    if (cmd == OP_READ_MEM || cmd == OP_WRITE_MEM) {
        if (copy_from_user(&cm, (void __user *)arg, sizeof(cm))) return -EFAULT;
        kbuf = kmalloc(cm.size, GFP_KERNEL);
        if (!kbuf) return -ENOMEM;
    }
    
    // Uprobe 配置处理
    if (cmd == OP_ADD_UPROBE || cmd == OP_DEL_UPROBE) {
        if (copy_from_user(&uc, (void __user *)arg, sizeof(uc))) return -EFAULT;
    }

    switch (cmd) {
        case OP_READ_MEM: {
            pid_struct = find_get_pid(cm.pid);
            if (pid_struct) {
                task = get_pid_task(pid_struct, PIDTYPE_PID);
                if (task) {
                    mm = get_task_mm(task);
                    if (mm) {
                        if (read_memory_force(mm, cm.addr, kbuf, cm.size) == 0) {
                            if (copy_to_user(cm.buffer, kbuf, cm.size)) ret = -EFAULT;
                            else ret = 0;
                        }
                        mmput(mm);
                    }
                    put_task_struct(task);
                }
                put_pid(pid_struct);
            }
        } break;

        case OP_WRITE_MEM: {
            if (copy_from_user(kbuf, cm.buffer, cm.size)) {
                kfree(kbuf); return -EFAULT;
            }
            pid_struct = find_get_pid(cm.pid);
            if (pid_struct) {
                task = get_pid_task(pid_struct, PIDTYPE_PID);
                if (task) {
                    mm = get_task_mm(task);
                    if (mm) {
                        if (write_memory_force(mm, cm.addr, kbuf, cm.size) == 0) ret = 0;
                        mmput(mm);
                    }
                    put_task_struct(task);
                }
                put_pid(pid_struct);
            }
        } break;

        // 处理 Uprobe
        case OP_ADD_UPROBE:
            ret = add_uprobe(uc.pid, uc.addr);
            break;
            
        case OP_DEL_UPROBE:
            ret = del_uprobe(uc.pid, uc.addr);
            break;
        
        default:
            ret = 0;
            break;
    }

    if (kbuf) kfree(kbuf);
    return ret;
}

// --- 驱动注册逻辑 ---
static struct file_operations fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = shami_ioctl,
    .compat_ioctl = shami_ioctl,
};

static int major;
static struct class *shami_class;

static int __init shami_init(void) {
    major = register_chrdev(0, DEVICE_NAME, &fops);
    if (major < 0) return major;
    shami_class = class_create(THIS_MODULE, DEVICE_NAME);
    device_create(shami_class, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);
    printk(KERN_INFO "[Shami] Driver Loaded with Uprobe support.\n");
    return 0;
}

static void __exit shami_exit(void) {
    // 卸载前必须清除所有探针，否则会崩溃
    clean_all_uprobes();
    
    device_destroy(shami_class, MKDEV(major, 0));
    class_destroy(shami_class);
    unregister_chrdev(major, DEVICE_NAME);
    printk(KERN_INFO "[Shami] Driver Unloaded.\n");
}

module_init(shami_init);
module_exit(shami_exit);
MODULE_LICENSE("GPL");
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
