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
// >>>>>>>>>> Kprobe 拦截逻辑 (修正版) <<<<<<<<<<
// ==========================================

// 目标函数: send_sig_fault(int sig, int code, void __user *addr, ...)
// 寄存器参数: X0=sig, X1=code, X2=addr
static int my_kprobe_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    int sig = regs->regs[0];        // X0: 信号
    uintptr_t fault_addr = regs->regs[2]; // X2: 故障地址

    // 1. 检查进程
    if (g_target_pid == 0 || current->tgid != g_target_pid) {
        return 0; 
    }

    // 2. 检查信号 (SIGTRAP=5) 和 地址
    // 注意：send_sig_fault 是非常底层的函数，一定要匹配地址，防止拦截错误
    if (sig == 5 && fault_addr == g_target_addr) {
        
        printk(KERN_ALERT "\n[Shami] >>> SWBP HIT! Intercepted send_sig_fault <<<\n");
        
        // 获取用户态崩溃时的寄存器
        struct pt_regs *user_regs = task_pt_regs(current);
        if (user_regs) {
            printk(KERN_ALERT "PC: %016llx  SP: %016llx\n", user_regs->pc, user_regs->sp);
            // 打印参数 X0-X8
            printk(KERN_ALERT "X0: %016llx  X1: %016llx\n", user_regs->regs[0], user_regs->regs[1]);
            printk(KERN_ALERT "X2: %016llx  X3: %016llx\n", user_regs->regs[2], user_regs->regs[3]);
            printk(KERN_ALERT "X4: %016llx  X5: %016llx\n", user_regs->regs[4], user_regs->regs[5]);
            printk(KERN_ALERT "X6: %016llx  X7: %016llx\n", user_regs->regs[6], user_regs->regs[7]);
        }

        // 3. 还原指令
        if (g_orig_insn != 0) {
            // 还原为原始指令
            write_memory_force(current->mm, g_target_addr, &g_orig_insn, 4);
            printk(KERN_ALERT "[Shami] Instruction restored: %x\n", g_orig_insn);
        }

        // 4. [魔法] 跳过原函数执行
        // 将 PC 设置为 LR (返回地址)，直接从 send_sig_fault 返回
        instruction_pointer_set(regs, regs->regs[30]);

        return 1; // Skip execution
    }

    return 0;
}

static struct kprobe kp = {
    // [修改点] 改为 send_sig_fault，这是更底层的函数
    .symbol_name = "send_sig_fault", 
    .pre_handler = my_kprobe_pre_handler,
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

            // 1. 注册 Kprobe (如果之前没注册)
            if (!g_kprobe_registered) {
                int err = register_kprobe(&kp);
                if (err < 0) {
                    printk(KERN_ERR "[Shami] Failed to hook send_sig_fault: %d\n", err);
                    
                    // [备选方案] 如果 send_sig_fault 也不行，尝试 arm64_force_sig_fault
                    // printk(KERN_INFO "[Shami] Trying arm64_force_sig_fault...\n");
                    // kp.symbol_name = "arm64_force_sig_fault";
                    // register_kprobe(&kp);
                    return err;
                }
                g_kprobe_registered = true;
                printk(KERN_INFO "[Shami] Kprobe hooked on: %s\n", kp.symbol_name);
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
    printk(KERN_INFO "[Shami] Driver Loaded (Hook: send_sig_fault).\n");
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
