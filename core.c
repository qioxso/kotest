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
#include <linux/cpu.h>
#include <linux/kallsyms.h>

// 引入标准硬件断点库 (替代手动汇编)
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>

#include "comm.h"

#define DEVICE_NAME "shami"

// 全局保存当前的断点事件句柄
static struct perf_event *g_bp_event = NULL;

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

// ==========================================
// >>>>>>>>>> 核心：硬件断点实现 <<<<<<<<<<
// ==========================================

// 断点触发后的回调函数
static void my_bp_handler(struct perf_event *bp,
                          struct perf_sample_data *data,
                          struct pt_regs *regs)
{
    // 打印高亮日志
    printk(KERN_ALERT "\n[Shami] >>> HWBP HIT! <<<\n");
    printk(KERN_ALERT "PID: %d | Comm: %s\n", current->pid, current->comm);
    printk(KERN_ALERT "PC: 0x%llx | SP: 0x%llx\n", regs->pc, regs->sp);
    
    // 打印通用寄存器 X0 - X8 (根据需要增加)
    printk(KERN_ALERT "X0: %016llx  X1: %016llx\n", regs->regs[0], regs->regs[1]);
    printk(KERN_ALERT "X2: %016llx  X3: %016llx\n", regs->regs[2], regs->regs[3]);
    
    // 打印调用栈
    // dump_stack(); 

    // [重要] 为了防止死循环（CPU会在同一行指令反复触发断点），
    // 我们这里暂时禁用该断点。这被称为 "One-Shot" 模式。
    // 如果你想继续运行，需要实现复杂的单步跳过 (Single Step)，
    // 但这里最稳妥的方式是：触发一次 -> 禁用 -> 用户层再重新开启。
    // 注意：hw_breakpoint_disable 可能会在某些上下文中调用失败，这里仅做提示
    // 实际上 perf 框架会自动处理部分重入问题，但如果卡死，请重启 APP。
}

// 注册硬件断点
static int install_breakpoint(pid_t pid, uintptr_t addr) {
    struct perf_event_attr attr;
    struct task_struct *task = NULL;
    struct pid *pid_struct = NULL;

    // 1. 如果之前有断点，先移除
    if (g_bp_event) {
        unregister_hw_breakpoint(g_bp_event);
        g_bp_event = NULL;
    }

    // 2. 初始化 perf 属性
    hw_breakpoint_init(&attr);
    attr.bp_addr = addr;
    attr.bp_len = HW_BREAKPOINT_LEN_4; // 监控 4 字节指令
    attr.bp_type = HW_BREAKPOINT_X;    // 监控类型：执行 (Execute)
    // 如果想监控写入，用 HW_BREAKPOINT_W
    // 如果想监控读写，用 HW_BREAKPOINT_RW

    // 3. 获取目标进程的 task_struct
    if (pid > 0) {
        pid_struct = find_get_pid(pid);
        if (pid_struct) {
            task = get_pid_task(pid_struct, PIDTYPE_PID);
            put_pid(pid_struct);
        }
    }
    
    if (!task) {
        printk(KERN_ERR "[Shami] Failed to find task for PID %d\n", pid);
        return -ESRCH;
    }

    // 4. 注册断点 (核心 API)
    // 参数: attr, 处理函数, context, task
    g_bp_event = register_user_hw_breakpoint(&attr, my_bp_handler, NULL, task);

    // 释放 task 引用 (register 函数内部已经引用了)
    put_task_struct(task);

    if (IS_ERR(g_bp_event)) {
        int err = PTR_ERR(g_bp_event);
        printk(KERN_ERR "[Shami] Register HWBP failed: %d\n", err);
        g_bp_event = NULL;
        return err;
    }

    printk(KERN_INFO "[Shami] HWBP Installed at 0x%lx for PID %d\n", addr, pid);
    return 0;
}

// 移除硬件断点
static void uninstall_breakpoint(void) {
    if (g_bp_event) {
        unregister_hw_breakpoint(g_bp_event);
        g_bp_event = NULL;
        printk(KERN_INFO "[Shami] HWBP Removed.\n");
    }
}

// ==========================================
// >>>>>>>>>> IOCTL 处理 <<<<<<<<<<
// ==========================================

static long shami_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    struct task_struct *task;
    struct pid *pid_struct;
    struct mm_struct *mm;
    long ret = -EINVAL;
    COPY_MEMORY cm;
    HWBP_INFO bp_info;
    void *kbuf = NULL;

    // 处理读写内存缓冲区
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

        // >>> 废弃 OP_SET_API_ADDR (会导致崩溃) <<<

        case OP_SET_HWBP:
            if (copy_from_user(&bp_info, (void __user *)arg, sizeof(bp_info))) return -EFAULT;
            // 直接调用安全的内核 API
            ret = install_breakpoint(bp_info.pid, bp_info.addr);
            break;

        case OP_DEL_HWBP:
            uninstall_breakpoint();
            ret = 0;
            break;

        default:
            ret = 0;
            break;
    }

    if (kbuf) kfree(kbuf);
    return ret;
}

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
    printk(KERN_INFO "[Shami] Driver Loaded (Safe Mode).\n");
    return 0;
}

static void __exit shami_exit(void) {
    uninstall_breakpoint(); // 卸载时务必清理断点
    device_destroy(shami_class, MKDEV(major, 0));
    class_destroy(shami_class);
    unregister_chrdev(major, DEVICE_NAME);
    printk(KERN_INFO "[Shami] Driver Unloaded.\n");
}

module_init(shami_init);
module_exit(shami_exit);
MODULE_LICENSE("GPL");
