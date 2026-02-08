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
#include <linux/kallsyms.h>
// 我们不再用 linux/hw_breakpoint.h，因为我们要手动操作
#include <asm/debug-monitors.h> 

#include "comm.h"

#define DEVICE_NAME "shami"

// 全局变量
static pid_t g_target_pid = 0;
static uintptr_t g_target_addr = 0;
static bool g_bp_installed = false;

// ==========================================
// >>>>>>>>>> GUP (必须保留) <<<<<<<<<<
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
// >>>>>>>>>> 核心：暴力汇编操作 <<<<<<<<<<
// ==========================================

// 在当前 CPU 上强行安装
static void install_force_on_cpu(void *info) {
    unsigned long addr = g_target_addr;
    u32 ctrl;

    // 1. 解锁 OSLAR (允许写调试寄存器)
    asm volatile("msr oslar_el1, xzr" : : : "memory");
    isb();

    // 2. [核弹操作] 暴力关闭所有槽位 (0-5)
    // 既然系统占满了，我们就全部关掉，腾出位置
    // 注意：这可能会导致系统自带的性能监控失效，但为了调试只能这样
    asm volatile("msr dbgbcr0_el1, %0" : : "r" (0UL));
    asm volatile("msr dbgbcr1_el1, %0" : : "r" (0UL));
    asm volatile("msr dbgbcr2_el1, %0" : : "r" (0UL));
    asm volatile("msr dbgbcr3_el1, %0" : : "r" (0UL));
    asm volatile("msr dbgbcr4_el1, %0" : : "r" (0UL));
    asm volatile("msr dbgbcr5_el1, %0" : : "r" (0UL));
    isb();

    // 3. 强行写入 Slot 0
    asm volatile("msr dbgbvr0_el1, %0" : : "r" (addr));
    
    // 配置控制位: Enable=1, EL0=1(User), Type=EXEC
    // 0x1 (Enable) | 0x2 (EL0 only) | 0x1E0 (Byte select 0xF << 5)
    ctrl = (1 << 0) | (1 << 1) | (0xf << 5); 
    
    asm volatile("msr dbgbcr0_el1, %0" : : "r" ((unsigned long)ctrl));
    isb();
}

// 在当前 CPU 上强行卸载
static void uninstall_force_on_cpu(void *info) {
    asm volatile("msr oslar_el1, xzr" : : : "memory");
    isb();
    // 仅关闭 Slot 0
    asm volatile("msr dbgbcr0_el1, %0" : : "r" (0UL));
    isb();
}

// 简单的异常处理 (需要配合 register_debug_fault_handler)
// 如果找不到内核符号，这一步是最大的难点。
// 我们先通过“写寄存器不报错”来验证是否能断下来。
// 为了能收到断点，我们需要注册 hook。
// 如果你之前 hook 崩溃了，我们这里先不注册 hook，
// 而是看系统日志会不会报 "Unhandled Debug Exception"
// 只要报了这个错，就说明断点生效了！

// ==========================================
// >>>>>>>>>> IOCTL <<<<<<<<<<
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
            
            g_target_pid = bp_info.pid;
            g_target_addr = bp_info.addr;
            g_bp_installed = true;

            // 在所有 CPU 上执行暴力写入
            // cpus_read_lock / unlock 是 5.10 的 API
            cpus_read_lock();
            on_each_cpu(install_force_on_cpu, NULL, 1);
            cpus_read_unlock();
            
            printk(KERN_ALERT "[Shami] FORCE INSTALLED HWBP at 0x%lx\n", g_target_addr);
            ret = 0;
            break;

        case OP_DEL_HWBP:
            g_bp_installed = false;
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

// ... 驱动注册部分保持不变 ...
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
    printk(KERN_INFO "[Shami] Driver Loaded (NUCLEAR MODE).\n");
    return 0;
}

static void __exit shami_exit(void) {
    // 卸载前清理
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
