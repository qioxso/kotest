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
// >>>>>>>>>> 通用 Hook 处理逻辑 (上帝视角版) <<<<<<<<<<
// ==========================================

// 不管 Hook 到了哪个函数，我们都不看它的参数
// 直接看 current (当前进程) 的状态
static int common_handler(struct pt_regs *regs, const char* hook_name)
{
    // 1. 检查进程 (最快过滤)
    if (g_target_pid == 0 || current->tgid != g_target_pid) {
        return 0; 
    }

    // 2. [关键修改] 获取用户态当前的 PC 指针
    struct pt_regs *user_regs = task_pt_regs(current);
    if (!user_regs) return 0;

    uintptr_t current_pc = user_regs->pc;

    // 3. 直接比对 PC 和 断点地址
    // 只有当 CPU 刚好停在我们的断点地址上，准备发信号时，才拦截
    if (current_pc == g_target_addr) {
        
        printk(KERN_ALERT "\n[Shami] >>> SWBP HIT! Hook: %s <<<\n", hook_name);
        
        // 打印寄存器
        printk(KERN_ALERT "PC: %016llx  SP: %016llx\n", user_regs->pc, user_regs->sp);
        printk(KERN_ALERT "X0: %016llx  X1: %016llx\n", user_regs->regs[0], user_regs->regs[1]);
        printk(KERN_ALERT "X2: %016llx  X3: %016llx\n", user_regs->regs[2], user_regs->regs[3]);
        printk(KERN_ALERT "X4: %016llx  X5: %016llx\n", user_regs->regs[4], user_regs->regs[5]);
        // 打印 X8 (返回值/系统调用号常驻地)
        printk(KERN_ALERT "X8: %016llx\n", user_regs->regs[8]);

        // 4. 还原指令
        if (g_orig_insn != 0) {
            write_memory_force(current->mm, g_target_addr, &g_orig_insn, 4);
            printk(KERN_ALERT "[Shami] Instruction restored: %08x\n", g_orig_insn);
        }

        // 5. [魔法] 跳过发信号函数
        // 将 Kernel PC 设置为 LR (返回地址)，让内核函数直接返回
        instruction_pointer_set(regs, regs->regs[30]);

        // 返回 1: 告诉 Kprobe "我修改了执行流，不要继续执行原指令了"
        return 1; 
    }

    return 0;
}

// Hook 1: force_sig_fault (通用)
static int handler_force_sig(struct kprobe *p, struct pt_regs *regs) {
    // 信号值在 regs->regs[0]。必须是 SIGTRAP(5) 才处理，防止拦截了空指针 crash
    if (regs->regs[0] != 5) return 0;
    return common_handler(regs, "force_sig_fault");
}

// Hook 2: send_sig_fault (底层)
static int handler_send_sig(struct kprobe *p, struct pt_regs *regs) {
    if (regs->regs[0] != 5) return 0;
    return common_handler(regs, "send_sig_fault");
}

static struct kprobe kp1 = {
    .symbol_name = "force_sig_fault",
    .pre_handler = handler_force_sig,
};

static struct kprobe kp2 = {
    .symbol_name = "send_sig_fault",
    .pre_handler = handler_send_sig,
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

            // 1. 注册 Kprobes (如果未注册)
            if (!g_kprobes_registered) {
                int count = 0;
                if (register_kprobe(&kp1) >= 0) count++;
                else printk(KERN_ERR "[Shami] Failed hook kp1\n");
                
                if (register_kprobe(&kp2) >= 0) count++;
                else printk(KERN_ERR "[Shami] Failed hook kp2\n");

                if (count > 0) {
                    g_kprobes_registered = true;
                    printk(KERN_INFO "[Shami] Kprobes active. Hooks installed: %d\n", count);
                } else {
                    return -EFAULT;
                }
            }

            // 2. 写入 BRK
            pid_struct = find_get_pid(g_target_pid);
            if (pid_struct) {
                task = get_pid_task(pid_struct, PIDTYPE_PID);
                if (task) {
                    mm = get_task_mm(task);
                    if (mm) {
                        if (write_memory_force(mm, g_target_addr, &brk_opcode, 4) == 0) {
                             printk(KERN_ALERT "[Shami] SWBP Set at %lx. Waiting for trigger...\n", g_target_addr);
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
    printk(KERN_INFO "[Shami] Driver Loaded (PC-Check Mode).\n");
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
