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
#include <linux/kdebug.h> // 必须引入，用于 die_notifier
#include <linux/notifier.h>
#include <asm/debug-monitors.h> 

#include "comm.h"

#define DEVICE_NAME "shami"

// 全局变量
static pid_t g_target_pid = 0;
static uintptr_t g_target_addr = 0;

// ==========================================
// >>>>>>>>>> GUP (保留原样) <<<<<<<<<<
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
// >>>>>>>>>> 核心：异常截获 (打印堆栈) <<<<<<<<<<
// ==========================================

// 当硬件断点触发，但没有 perf 处理时，内核会发送 die notification
static int my_die_handler(struct notifier_block *self, unsigned long val, void *data)
{
    struct die_args *args = (struct die_args *)data;
    struct pt_regs *regs = args->regs;

    // 过滤：如果不是我们关注的进程，直接忽略，让系统自己处理（可能会导致crash）
    if (g_target_pid != 0 && current->tgid != g_target_pid) {
        return NOTIFY_DONE; 
    }

    // 只有当原因是 Debug 异常时才处理 (DIE_DEBUG 在 arm64 上通常对应 1)
    // 但为了保险，我们只要是这个进程的异常都打印一下看看
    
    printk(KERN_ALERT "\n[Shami] >>> HIT! (Via Die Notifier) <<<\n");
    printk(KERN_ALERT "PID: %d | PC: 0x%llx | SP: 0x%llx\n", current->tgid, regs->pc, regs->sp);
    
    // 打印 X0 - X5
    printk(KERN_ALERT "X0: %016llx  X1: %016llx\n", regs->regs[0], regs->regs[1]);
    printk(KERN_ALERT "X2: %016llx  X3: %016llx\n", regs->regs[2], regs->regs[3]);
    printk(KERN_ALERT "X4: %016llx  X5: %016llx\n", regs->regs[4], regs->regs[5]);

    // 打印堆栈
    dump_stack();

    // [关键] 为了防止死循环，我们必须在这里移除断点
    // 因为这是在异常上下文中，我们不能简单地调用 uninstall，只能暂时让它通过
    // 但硬件断点是顽固的，不关掉就会无限触发。
    // 这里我们尝试修改寄存器关闭断点 (简单粗暴)
    asm volatile("msr dbgbcr0_el1, %0" : : "r" (0UL));
    isb();

    printk(KERN_ALERT "[Shami] HWBP Disabled automatically.\n");

    return NOTIFY_STOP; // 告诉内核：我已经处理了这个异常，不要杀掉进程
}

static struct notifier_block my_nb = {
    .notifier_call = my_die_handler,
    .priority = 0x7fffffff // 最高优先级
};

// ==========================================
// >>>>>>>>>> 核心：暴力汇编操作 (带总闸) <<<<<<<<<<
// ==========================================

static void install_force_on_cpu(void *info) {
    unsigned long addr = g_target_addr;
    u32 ctrl;
    u64 mdscr;

    // 1. 解锁 OSLAR
    asm volatile("msr oslar_el1, xzr" : : : "memory");
    isb();

    // 2. [新增] 开启总闸 MDSCR_EL1 (Monitor Debug System Control Register)
    // 读取当前值
    asm volatile("mrs %0, mdscr_el1" : "=r" (mdscr));
    // 检查 Bit 15 (MDE - Monitor Debug Enable) 是否开启
    if ((mdscr & (1UL << 15)) == 0) {
        mdscr |= (1UL << 15); // 强制开启 MDE
        asm volatile("msr mdscr_el1, %0" : : "r" (mdscr));
        isb();
    }
    // 确保 KDE (Kernel Debug Enable) 也是开启的 (Bit 13)，虽然我们监控用户态
    if ((mdscr & (1UL << 13)) == 0) {
        mdscr |= (1UL << 13); 
        asm volatile("msr mdscr_el1, %0" : : "r" (mdscr));
        isb();
    }

    // 3. 暴力关闭所有槽位，腾出空间
    asm volatile("msr dbgbcr0_el1, %0" : : "r" (0UL));
    asm volatile("msr dbgbcr1_el1, %0" : : "r" (0UL));
    asm volatile("msr dbgbcr2_el1, %0" : : "r" (0UL));
    asm volatile("msr dbgbcr3_el1, %0" : : "r" (0UL));
    asm volatile("msr dbgbcr4_el1, %0" : : "r" (0UL));
    asm volatile("msr dbgbcr5_el1, %0" : : "r" (0UL));
    isb();

    // 4. 写入 Slot 0
    asm volatile("msr dbgbvr0_el1, %0" : : "r" (addr));
    
    // Enable=1, PMC=0x3 (EL0+EL1), BAS=0xF
    // 开启用户态和内核态监控，确保不错过
    ctrl = (1 << 0) | (3 << 1) | (0xf << 5); 
    
    asm volatile("msr dbgbcr0_el1, %0" : : "r" ((unsigned long)ctrl));
    isb();
}

static void uninstall_force_on_cpu(void *info) {
    asm volatile("msr oslar_el1, xzr" : : : "memory");
    isb();
    asm volatile("msr dbgbcr0_el1, %0" : : "r" (0UL));
    isb();
}

// ==========================================
// >>>>>>>>>> IOCTL <<<<<<<<<<
// ==========================================

static long shami_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
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
            // 简单实现 GUP 调用
            if (read_memory_force(current->mm, cm.addr, kbuf, cm.size) == 0) {
                 if (copy_to_user(cm.buffer, kbuf, cm.size)) ret = -EFAULT;
                 else ret = 0;
            }
            break;
        case OP_WRITE_MEM:
            // 简单实现 GUP 调用
            if (write_memory_force(current->mm, cm.addr, kbuf, cm.size) == 0) ret = 0;
            break;

        case OP_SET_HWBP:
            if (copy_from_user(&bp_info, (void __user *)arg, sizeof(bp_info))) return -EFAULT;
            
            g_target_pid = bp_info.pid;
            g_target_addr = bp_info.addr;

            // 注册异常通知链 (只注册一次)
            // 这样当异常发生时，my_die_handler 会被调用
            register_die_notifier(&my_nb);

            cpus_read_lock();
            on_each_cpu(install_force_on_cpu, NULL, 1);
            cpus_read_unlock();
            
            printk(KERN_ALERT "[Shami] FORCE INSTALLED HWBP + MDSCR Enabled\n");
            ret = 0;
            break;

        case OP_DEL_HWBP:
            unregister_die_notifier(&my_nb);
            cpus_read_lock();
            on_each_cpu(uninstall_force_on_cpu, NULL, 1);
            cpus_read_unlock();
            printk(KERN_ALERT "[Shami] FORCE REMOVED HWBP\n");
            ret = 0;
            break;

        default:
            ret = 0;
            break;
    }

    if (kbuf) kfree(kbuf);
    return ret;
}

// ==========================================
// >>>>>>>>>> 驱动注册 <<<<<<<<<<
// ==========================================

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
    printk(KERN_INFO "[Shami] Driver Loaded (NUCLEAR V2 - Die Notifier).\n");
    return 0;
}

static void __exit shami_exit(void) {
    unregister_die_notifier(&my_nb);
    cpus_read_lock();
    on_each_cpu(uninstall_force_on_cpu, NULL, 1);
    cpus_read_unlock();
    device_destroy(shami_class, MKDEV(major, 0));
    class_destroy(shami_class);
    unregister_chrdev(major, DEVICE_NAME);
}

module_init(shami_init);
module_exit(shami_exit);
MODULE_LICENSE("GPL");
