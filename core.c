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
#include <linux/signal.h> // for siginfo

#include "comm.h"

#define DEVICE_NAME "shami"

// 全局变量
static pid_t g_target_pid = 0;
static uintptr_t g_target_addr = 0;
static uint32_t g_orig_insn = 0;
static bool g_kprobes_registered = false;

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
// >>>>>>>>>> 核心：Hook force_sig_info <<<<<<<<<<
// ==========================================

// int force_sig_info(struct kernel_siginfo *info);
// X0 = info 指针
static int handler_force_sig_info(struct kprobe *p, struct pt_regs *regs)
{
    // 1. 快速检查进程
    if (g_target_pid == 0 || current->tgid != g_target_pid) {
        return 0; 
    }

    // 2. 解析 siginfo (位于 X0 寄存器)
    struct kernel_siginfo *info = (struct kernel_siginfo *)regs->regs[0];
    if (!info) return 0;

    // 3. 检查信号类型 (SIGTRAP = 5)
    // kernel_siginfo 的第一个成员通常就是 si_signo
    if (info->si_signo != SIGTRAP) {
        return 0;
    }

    // 4. 上帝视角检查：当前用户态 PC 是否在断点处？
    struct pt_regs *user_regs = task_pt_regs(current);
    if (!user_regs) return 0;

    if (user_regs->pc == g_target_addr) {
        
        printk(KERN_ALERT "\n[Shami] >>> SWBP HIT! (Intercepted force_sig_info) <<<\n");
        
        // 打印寄存器
        printk(KERN_ALERT "PC: %016llx  SP: %016llx\n", user_regs->pc, user_regs->sp);
        printk(KERN_ALERT "X0: %016llx  X1: %016llx\n", user_regs->regs[0], user_regs->regs[1]);
        printk(KERN_ALERT "X2: %016llx  X3: %016llx\n", user_regs->regs[2], user_regs->regs[3]);
        printk(KERN_ALERT "X4: %016llx  X5: %016llx\n", user_regs->regs[4], user_regs->regs[5]);
        printk(KERN_ALERT "X8: %016llx  LR: %016llx\n", user_regs->regs[8], user_regs->regs[30]);

        // 5. 还原指令
        if (g_orig_insn != 0) {
            write_memory_force(current->mm, g_target_addr, &g_orig_insn, 4);
            printk(KERN_ALERT "[Shami] Instruction restored.\n");
        }

        // 6. 跳过原函数
        // 让 force_sig_info 直接返回，不发送信号
        instruction_pointer_set(regs, regs->regs[30]);

        return 1;
    }

    return 0;
}

static struct kprobe kp_info = {
    .symbol_name = "force_sig_info",
    .pre_handler = handler_force_sig_info,
};

// 备用 Hook：force_sig (有些内核通过这个封装)
static int handler_force_sig(struct kprobe *p, struct pt_regs *regs)
{
    // force_sig(int sig) -> X0 是信号值
    if (g_target_pid != 0 && current->tgid == g_target_pid && regs->regs[0] == SIGTRAP) {
        struct pt_regs *user_regs = task_pt_regs(current);
        if (user_regs && user_regs->pc == g_target_addr) {
            printk(KERN_ALERT "\n[Shami] >>> SWBP HIT! (Intercepted force_sig) <<<\n");
            // 打印、还原、跳过逻辑同上
            printk(KERN_ALERT "PC: %016llx\n", user_regs->pc);
            printk(KERN_ALERT "X0: %016llx  X1: %016llx\n", user_regs->regs[0], user_regs->regs[1]);
            
            if (g_orig_insn != 0) write_memory_force(current->mm, g_target_addr, &g_orig_insn, 4);
            instruction_pointer_set(regs, regs->regs[30]);
            return 1;
        }
    }
    return 0;
}

static struct kprobe kp_sig = {
    .symbol_name = "force_sig",
    .pre_handler = handler_force_sig,
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

            // 1. 注册 Hook (force_sig_info 和 force_sig)
            if (!g_kprobes_registered) {
                int c = 0;
                if (register_kprobe(&kp_info) >= 0) {
                     printk(KERN_INFO "[Shami] Hooked force_sig_info\n");
                     c++;
                }
                if (register_kprobe(&kp_sig) >= 0) {
                     printk(KERN_INFO "[Shami] Hooked force_sig\n");
                     c++;
                }
                
                if (c > 0) g_kprobes_registered = true;
                else printk(KERN_ERR "[Shami] Failed to hook any signal function!\n");
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
            if (g_kprobes_registered) {
                unregister_kprobe(&kp_info);
                unregister_kprobe(&kp_sig);
                g_kprobes_registered = false;
                printk(KERN_INFO "[Shami] Hooks removed.\n");
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
    printk(KERN_INFO "[Shami] Driver Loaded (Hook force_sig_info).\n");
    return 0;
}

static void __exit shami_exit(void) {
    if (g_kprobes_registered) {
        unregister_kprobe(&kp_info);
        unregister_kprobe(&kp_sig);
    }
    device_destroy(shami_class, MKDEV(major, 0));
    class_destroy(shami_class);
    unregister_chrdev(major, DEVICE_NAME);
}

module_init(shami_init);
module_exit(shami_exit);
MODULE_LICENSE("GPL");
