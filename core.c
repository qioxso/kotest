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
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>

#include "comm.h"

#define DEVICE_NAME "shami"

// 保存 CPU 全局断点的指针
static struct perf_event * __percpu *g_bp_events = NULL;
// 全局过滤 PID
static pid_t g_target_pid = 0; 

// ==========================================
// >>>>>>>>>> GUP 内存读写辅助函数 <<<<<<<<<<
// ==========================================

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
// >>>>>>>>>> 核心：强力抢占断点 <<<<<<<<<<
// ==========================================

// 断点触发回调
static void my_bp_handler(struct perf_event *bp,
                          struct perf_sample_data *data,
                          struct pt_regs *regs)
{
    // 过滤器：如果不是目标进程，直接返回
    if (g_target_pid != 0 && current->tgid != g_target_pid) {
        return; 
    }

    printk(KERN_ALERT "\n[Shami] >>> HIT! PID: %d (Comm: %s) <<<\n", current->tgid, current->comm);
    printk(KERN_ALERT "PC: 0x%llx | LR: 0x%llx | SP: 0x%llx\n", regs->pc, regs->regs[30], regs->sp);
    printk(KERN_ALERT "X0: %016llx  X1: %016llx\n", regs->regs[0], regs->regs[1]);
    printk(KERN_ALERT "X2: %016llx  X3: %016llx\n", regs->regs[2], regs->regs[3]);
    
    // [修复点] 使用 perf_event_disable 替代 hw_breakpoint_disable
    // 这里的 bp 就是 struct perf_event 指针
    perf_event_disable(bp);
    
    printk(KERN_ALERT "[Shami] Breakpoint disabled to prevent loop.\n");
}

// 安装全局断点 (带 Pinned 属性)
static int install_wide_breakpoint(pid_t pid, uintptr_t addr) {
    struct perf_event_attr attr;
    int err;

    if (g_bp_events) {
        unregister_wide_hw_breakpoint(g_bp_events);
        g_bp_events = NULL;
    }

    g_target_pid = pid;

    hw_breakpoint_init(&attr);
    attr.bp_addr = addr;
    attr.bp_len = HW_BREAKPOINT_LEN_4;
    attr.bp_type = HW_BREAKPOINT_X;
    
    // >>> 关键修改点: 强占模式 <<<
    attr.pinned = 1;     // 必须驻留
    attr.exclusive = 1;  // 独占模式

    g_bp_events = register_wide_hw_breakpoint(&attr, my_bp_handler, NULL);

    if (IS_ERR((void __force *)g_bp_events)) {
        err = PTR_ERR((void __force *)g_bp_events);
        printk(KERN_ERR "[Shami] Failed to install PINNED HWBP: %d\n", err);
        g_bp_events = NULL;
        return err;
    }

    printk(KERN_INFO "[Shami] PINNED HWBP Installed at 0x%lx\n", addr);
    return 0;
}

static void uninstall_wide_breakpoint(void) {
    if (g_bp_events) {
        unregister_wide_hw_breakpoint(g_bp_events);
        g_bp_events = NULL;
        printk(KERN_INFO "[Shami] HWBP Removed.\n");
    }
}

// ==========================================
// >>>>>>>>>> IOCTL 处理逻辑 <<<<<<<<<<
// ==========================================

static long shami_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    struct task_struct *task;
    struct pid *pid_struct;
    struct mm_struct *mm;
    long ret = -EINVAL;
    COPY_MEMORY cm;
    HWBP_INFO bp_info;
    void *kbuf = NULL;

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

        case OP_SET_HWBP:
            if (copy_from_user(&bp_info, (void __user *)arg, sizeof(bp_info))) return -EFAULT;
            ret = install_wide_breakpoint(bp_info.pid, bp_info.addr);
            break;

        case OP_DEL_HWBP:
            uninstall_wide_breakpoint();
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
    printk(KERN_INFO "[Shami] Driver Loaded (Pinned/Force Mode).\n");
    return 0;
}

static void __exit shami_exit(void) {
    uninstall_wide_breakpoint();
    device_destroy(shami_class, MKDEV(major, 0));
    class_destroy(shami_class);
    unregister_chrdev(major, DEVICE_NAME);
    printk(KERN_INFO "[Shami] Driver Unloaded.\n");
}

module_init(shami_init);
module_exit(shami_exit);
MODULE_LICENSE("GPL");
