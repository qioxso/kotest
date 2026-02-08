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
static bool g_kprobes_registered = false;

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
// >>>>>>>>>> 通用 Hook 处理逻辑 <<<<<<<<<<
// ==========================================

// 这是一个通用的处理函数，不管 Hook 到了哪个内核函数，都调用这个
static int common_handler(struct pt_regs *regs, const char* hook_name)
{
    // 在 arm64 调用约定中，X2 通常是第三个参数。
    // arm64_force_sig_fault(sig, code, addr, ...) -> X2 是 addr
    // force_sig_ptrace_errno_trap(errno, addr)     -> X1 是 addr (注意!)
    
    uintptr_t x1_val = regs->regs[1];
    uintptr_t x2_val = regs->regs[2];

    // 1. 检查进程
    if (g_target_pid == 0 || current->tgid != g_target_pid) {
        return 0; 
    }

    // 2. 检查地址匹配
    // 因为不同函数参数位置不一样，我们两个寄存器都检查一下，
    // 只要有一个等于我们的断点地址，就认为是命中了。
    bool hit = false;
    if (x2_val == g_target_addr) hit = true;
    else if (x1_val == g_target_addr) hit = true;

    if (hit) {
        printk(KERN_ALERT "\n[Shami] >>> SWBP HIT! Intercepted by %s <<<\n", hook_name);
        
        // 获取用户态寄存器
        struct pt_regs *user_regs = task_pt_regs(current);
        if (user_regs) {
            printk(KERN_ALERT "PC: %016llx  SP: %016llx\n", user_regs->pc, user_regs->sp);
            printk(KERN_ALERT "X0: %016llx  X1: %016llx\n", user_regs->regs[0], user_regs->regs[1]);
            printk(KERN_ALERT "X2: %016llx  X3: %016llx\n", user_regs->regs[2], user_regs->regs[3]);
        }

        // 3. 还原指令
        if (g_orig_insn != 0) {
            write_memory_force(current->mm, g_target_addr, &g_orig_insn, 4);
            printk(KERN_ALERT "[Shami] Instruction restored.\n");
        }

        // 4. [魔法] 跳过原函数，直接返回
        instruction_pointer_set(regs, regs->regs[30]); // PC = LR

        return 1; // Skip execution
    }

    return 0;
}

// Hook 1: arm64_force_sig_fault
static int handler_arm64_force(struct kprobe *p, struct pt_regs *regs) {
    return common_handler(regs, "arm64_force_sig_fault");
}

// Hook 2: force_sig_ptrace_errno_trap (专门处理 ptrace/brkpt 的)
static int handler_ptrace_trap(struct kprobe *p, struct pt_regs *regs) {
    return common_handler(regs, "force_sig_ptrace_errno_trap");
}

static struct kprobe kp1 = {
    .symbol_name = "arm64_force_sig_fault",
    .pre_handler = handler_arm64_force,
};

static struct kprobe kp2 = {
    .symbol_name = "force_sig_ptrace_errno_trap",
    .pre_handler = handler_ptrace_trap,
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

            // 1. 注册双重 Kprobe
            if (!g_kprobes_registered) {
                int err1 = register_kprobe(&kp1);
                if (err1 < 0) printk(KERN_ERR "[Shami] Hook kp1 failed: %d\n", err1);
                else printk(KERN_INFO "[Shami] Hook kp1 success.\n");

                int err2 = register_kprobe(&kp2);
                if (err2 < 0) printk(KERN_ERR "[Shami] Hook kp2 failed: %d\n", err2);
                else printk(KERN_INFO "[Shami] Hook kp2 success.\n");

                g_kprobes_registered = true;
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
                unregister_kprobe(&kp1);
                unregister_kprobe(&kp2);
                g_kprobes_registered = false;
                printk(KERN_INFO "[Shami] Kprobes removed.\n");
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
    printk(KERN_INFO "[Shami] Driver Loaded (Dual-Hook).\n");
    return 0;
}

static void __exit shami_exit(void) {
    if (g_kprobes_registered) {
        unregister_kprobe(&kp1);
        unregister_kprobe(&kp2);
    }
    device_destroy(shami_class, MKDEV(major, 0));
    class_destroy(shami_class);
    unregister_chrdev(major, DEVICE_NAME);
}

module_init(shami_init);
module_exit(shami_exit);
MODULE_LICENSE("GPL");
