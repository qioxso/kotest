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
#include <linux/ptrace.h>
#include <linux/kprobes.h> 

#include "comm.h"

#define DEVICE_NAME "shami"

// 全局变量
static pid_t g_target_pid = 0;
static uintptr_t g_target_addr = 0;
static uint32_t g_orig_insn = 0;
static bool g_kprobe_registered = false;

// ==========================================
// >>>>>>>>>> GUP 内存读写 <<<<<<<<<<
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
// >>>>>>>>>> Kprobe 拦截 do_debug_exception <<<<<<<<<<
// ==========================================

// 函数原型：
// void do_debug_exception(unsigned long addr_if_watchpoint, unsigned int esr, struct pt_regs *regs)
// 参数寄存器: X0=addr, X1=esr, X2=regs(用户态寄存器指针)
static int handler_debug_exception(struct kprobe *p, struct pt_regs *kregs)
{
    // 1. 检查进程
    if (g_target_pid == 0 || current->tgid != g_target_pid) {
        return 0; 
    }

    // 2. 获取 do_debug_exception 的第三个参数 (X2)
    // 这个参数是指向用户态寄存器组 (struct pt_regs) 的指针
    struct pt_regs *user_regs = (struct pt_regs *)kregs->regs[2];
    
    // 安全检查：指针是否有效
    if (!user_regs) return 0;

    // 3. 检查断点地址
    // 用户态 PC 此时应该停在 BRK 指令上
    if (user_regs->pc == g_target_addr) {
        
        printk(KERN_ALERT "\n[Shami] >>> SWBP HIT! Intercepted do_debug_exception <<<\n");
        
        // 打印寄存器
        printk(KERN_ALERT "PC: %016llx  SP: %016llx\n", user_regs->pc, user_regs->sp);
        printk(KERN_ALERT "X0: %016llx  X1: %016llx\n", user_regs->regs[0], user_regs->regs[1]);
        printk(KERN_ALERT "X2: %016llx  X3: %016llx\n", user_regs->regs[2], user_regs->regs[3]);
        printk(KERN_ALERT "X4: %016llx  X5: %016llx\n", user_regs->regs[4], user_regs->regs[5]);
        printk(KERN_ALERT "LR: %016llx\n", user_regs->regs[30]);

        // 4. 还原指令
        if (g_orig_insn != 0) {
            write_memory_force(current->mm, g_target_addr, &g_orig_insn, 4);
            printk(KERN_ALERT "[Shami] Instruction restored: %08x\n", g_orig_insn);
        }

        // 5. [魔法] 跳过 do_debug_exception
        // 我们不想让内核继续处理这个异常（否则它会发现是 BRK 并发信号）
        // 我们直接让 do_debug_exception 返回 void
        // 方法：将内核 PC 设置为 LR (返回地址)
        instruction_pointer_set(kregs, kregs->regs[30]);

        return 1; // Skip original function
    }

    return 0;
}

static struct kprobe kp = {
    .symbol_name = "do_debug_exception",
    .pre_handler = handler_debug_exception,
};

// ==========================================
// >>>>>>>>>> IOCTL <<<<<<<<<<
// ==========================================

static long shami_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    struct task_struct *task;
    struct pid *pid_struct;
    struct mm_struct *mm;
    long ret = -EINVAL;
    COPY_MEMORY cm;
    SWBP_INFO bp_info;
    void *kbuf = NULL;
    uint32_t brk_opcode = 0xD4200000; 

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
            g_orig_insn = bp_info.orig_instruction;

            // 1. 注册 Kprobe (Hook 异常入口)
            if (!g_kprobe_registered) {
                int err = register_kprobe(&kp);
                if (err < 0) {
                    printk(KERN_ERR "[Shami] Failed to hook do_debug_exception: %d\n", err);
                    return err;
                }
                g_kprobe_registered = true;
                printk(KERN_INFO "[Shami] Hooked do_debug_exception.\n");
            }

            // 2. 写入 BRK
            pid_struct = find_get_pid(g_target_pid);
            if (pid_struct) {
                task = get_pid_task(pid_struct, PIDTYPE_PID);
                if (task) {
                    mm = get_task_mm(task);
                    if (mm) {
                        if (write_memory_force(mm, g_target_addr, &brk_opcode, 4) == 0) {
                             printk(KERN_ALERT "[Shami] SWBP Set at %lx\n", g_target_addr);
                             ret = 0;
                        } else {
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
            if (g_kprobe_registered) {
                unregister_kprobe(&kp);
                g_kprobe_registered = false;
                printk(KERN_INFO "[Shami] Kprobe removed.\n");
            }
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
    printk(KERN_INFO "[Shami] Driver Loaded (Hook do_debug_exception).\n");
    return 0;
}

static void __exit shami_exit(void) {
    if (g_kprobe_registered) unregister_kprobe(&kp);
    device_destroy(shami_class, MKDEV(major, 0));
    class_destroy(shami_class);
    unregister_chrdev(major, DEVICE_NAME);
}

module_init(shami_init);
module_exit(shami_exit);
MODULE_LICENSE("GPL");
