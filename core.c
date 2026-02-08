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
#include <linux/pid.h>
#include <linux/cpu.h>
#include <linux/kdebug.h>
#include <linux/notifier.h>
#include <asm/debug-monitors.h> 

#include "comm.h"

#define DEVICE_NAME "shami"

// 全局变量保存断点信息
static pid_t g_target_pid = 0;
static uintptr_t g_target_addr = 0;
static uint32_t g_orig_insn = 0; // 保存原始指令

// ==========================================
// >>>>>>>>>> GUP 内存读写 (保持不变) <<<<<<<<<<
// ==========================================

static int read_memory_force(struct mm_struct *mm, unsigned long addr, void *buffer, size_t size) {
    struct page *page;
    void *maddr;
    int res;
    size_t bytes_read = 0;
    
    mmap_read_lock(mm);
    while (bytes_read < size) {
        size_t offset = (addr + bytes_read) & ~PAGE_MASK;
        size_t bytes_to_copy = min(size - bytes_read, PAGE_SIZE - offset);
        res = get_user_pages_remote(mm, addr + bytes_read, 1, FOLL_FORCE, &page, NULL, NULL);
        if (res <= 0) { mmap_read_unlock(mm); return -1; }
        maddr = kmap_atomic(page);
        memcpy(buffer + bytes_read, maddr + offset, bytes_to_copy);
        kunmap_atomic(maddr);
        put_page(page);
        bytes_read += bytes_to_copy;
    }
    mmap_read_unlock(mm);
    return 0;
}

static int write_memory_force(struct mm_struct *mm, unsigned long addr, void *data, size_t size) {
    struct page *page;
    void *maddr;
    int res;
    size_t bytes_written = 0;

    mmap_read_lock(mm);
    while (bytes_written < size) {
        size_t offset = (addr + bytes_written) & ~PAGE_MASK;
        size_t bytes_to_copy = min(size - bytes_written, PAGE_SIZE - offset);
        res = get_user_pages_remote(mm, addr + bytes_written, 1, FOLL_WRITE | FOLL_FORCE, &page, NULL, NULL);
        if (res <= 0) { mmap_read_unlock(mm); return -1; }
        maddr = kmap_atomic(page);
        memcpy(maddr + offset, data + bytes_written, bytes_to_copy);
        kunmap_atomic(maddr);
        set_page_dirty_lock(page);
        put_page(page);
        bytes_written += bytes_to_copy;
    }
    mmap_read_unlock(mm);
    return 0;
}

// ==========================================
// >>>>>>>>>> 核心：异常截获 & 自动恢复 <<<<<<<<<<
// ==========================================

static int my_die_handler(struct notifier_block *self, unsigned long val, void *data)
{
    struct die_args *args = (struct die_args *)data;
    struct pt_regs *regs = args->regs;

    // 1. 过滤进程
    if (g_target_pid != 0 && current->tgid != g_target_pid) {
        return NOTIFY_DONE; 
    }

    // 2. 确认是否是我们的断点地址触发的异常
    // 注意：BRK 触发时，PC 指针通常指向 BRK 指令的地址
    if (regs->pc != g_target_addr) {
        return NOTIFY_DONE;
    }

    printk(KERN_ALERT "\n[Shami] >>> BP HIT! Resuming... <<<\n");
    // 打印你关心的寄存器
    printk(KERN_ALERT "PC: %016llx  X0: %016llx  X1: %016llx\n", regs->pc, regs->regs[0], regs->regs[1]);
    printk(KERN_ALERT "X2: %016llx  X3: %016llx  X8: %016llx\n", regs->regs[2], regs->regs[3], regs->regs[8]);
    
    // 3. [关键步骤] 还原指令！
    // 我们把原本的指令写回内存，覆盖掉 BRK
    // 因为我们在异常上下文中，直接用 write_memory_force 是最方便的
    // 注意：这里用 current->mm 是安全的，因为当前就是目标进程的上下文
    if (g_orig_insn != 0) {
        int ret = write_memory_force(current->mm, g_target_addr, &g_orig_insn, 4);
        if (ret == 0) {
            printk(KERN_ALERT "[Shami] Instruction restored: %08x\n", g_orig_insn);
        } else {
            printk(KERN_ERR "[Shami] Failed to restore instruction!\n");
            // 如果还原失败，App 肯定会崩溃，但我们尽力了
        }
    }

    // 4. [欺骗内核]
    // 返回 NOTIFY_STOP，告诉内核 "我处理完了，没事了"。
    // 内核会直接退出异常处理流程，让 CPU 重新执行当前的 PC。
    // 因为我们刚刚把 PC 处的指令改回了正确的指令，所以 APP 会继续正常运行！
    return NOTIFY_STOP;
}

static struct notifier_block my_nb = {
    .notifier_call = my_die_handler,
    .priority = 0x7fffffff
};

// ==========================================
// >>>>>>>>>> IOCTL <<<<<<<<<<
// ==========================================

static long shami_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    long ret = -EINVAL;
    COPY_MEMORY cm;
    SWBP_INFO bp_info;
    void *kbuf = NULL;
    uint32_t brk_opcode = 0xD4200000; // BRK #0 指令

    if (cmd == OP_READ_MEM || cmd == OP_WRITE_MEM) {
        if (copy_from_user(&cm, (void __user *)arg, sizeof(cm))) return -EFAULT;
        kbuf = kmalloc(cm.size, GFP_KERNEL);
        if (!kbuf) return -ENOMEM;
    }

    switch (cmd) {
        case OP_READ_MEM: 
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
            break;

        case OP_WRITE_MEM:
            // ... (同上，省略重复代码) ...
            if (copy_from_user(kbuf, cm.buffer, cm.size)) { kfree(kbuf); return -EFAULT; }
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
            break;

        case OP_SET_SWBP:
            if (copy_from_user(&bp_info, (void __user *)arg, sizeof(bp_info))) return -EFAULT;
            
            g_target_pid = bp_info.pid;
            g_target_addr = bp_info.addr;
            g_orig_insn = bp_info.orig_instruction; // 保存原始指令

            // 1. 注册异常捕获
            // 为了防止重复注册报错，先尝试卸载
            unregister_die_notifier(&my_nb);
            register_die_notifier(&my_nb);

            // 2. 写入 BRK 指令
            // 我们需要在内核里帮用户写入 BRK，而不是让用户在 test.cpp 里写
            // 这样更原子化
            pid_struct = find_get_pid(g_target_pid);
            if (pid_struct) {
                task = get_pid_task(pid_struct, PIDTYPE_PID);
                if (task) {
                    mm = get_task_mm(task);
                    if (mm) {
                        if (write_memory_force(mm, g_target_addr, &brk_opcode, 4) == 0) {
                             printk(KERN_ALERT "[Shami] SWBP Set at %lx. Backup: %08x\n", g_target_addr, g_orig_insn);
                             ret = 0;
                        } else {
                             printk(KERN_ERR "[Shami] Failed to write BRK instruction\n");
                             ret = -EFAULT;
                        }
                        mmput(mm);
                    }
                    put_task_struct(task);
                }
                put_pid(pid_struct);
            }
            break;

        case OP_DEL_SWBP:
            unregister_die_notifier(&my_nb);
            // 这里可选：如果用户想手动移除断点，也可以把 g_orig_insn 写回去
            // 但通常触发一次后就会自动移除
            printk(KERN_ALERT "[Shami] SWBP Removed\n");
            ret = 0;
            break;

        default:
            ret = 0;
            break;
    }

    if (kbuf) kfree(kbuf);
    return ret;
}

// ... 注册部分保持不变 ...
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
    printk(KERN_INFO "[Shami] Driver Loaded (Auto-Resume SWBP).\n");
    return 0;
}

static void __exit shami_exit(void) {
    unregister_die_notifier(&my_nb);
    device_destroy(shami_class, MKDEV(major, 0));
    class_destroy(shami_class);
    unregister_chrdev(major, DEVICE_NAME);
}

module_init(shami_init);
module_exit(shami_exit);
MODULE_LICENSE("GPL");
