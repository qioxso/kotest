// core.c
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
// 引入 ARM64 相关的头文件，用于处理寄存器
#include <asm/debug-monitors.h>
#include <asm/ptrace.h>

#include "comm.h"

#define DEVICE_NAME "shami"

// 定义函数指针类型，用于指向内核未导出的 hook 函数
// 根据内核版本不同，这里可能需要调整签名，通常是 hook_debug_fault_code
typedef int (*func_hook_debug_fault_code)(int nr, int (*fn)(unsigned long, unsigned int, struct pt_regs *), int sig, int code, const char *name);
static func_hook_debug_fault_code g_hook_debug_func = NULL;

// 全局保存断点信息
static struct _HWBP_INFO g_bp_info = {0};

// --- 辅助函数：GUP 强力读取 (保持不变) ---
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

// --- 辅助函数：GUP 强力写入 (保持不变) ---
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
// >>>>>>>>>> 核心新增：硬件断点实现 <<<<<<<<<<
// ==========================================

// 1. 异常处理回调：当断点触发时执行
static int my_hw_bp_handler(unsigned long addr, unsigned int esr, struct pt_regs *regs) {
    // 检查是否是我们关注的进程
    if (g_bp_info.pid != 0 && current->pid != g_bp_info.pid) {
        return 0; // 不是目标进程，不处理 (但硬件断点实际上已经暂停了 CPU)
    }

    printk(KERN_ALERT "[Shami] HWBP Hit! PID: %d, Addr: 0x%lx\n", current->pid, addr);
    
    // 打印通用寄存器 X0-X29
    int i;
    for (i = 0; i < 30; i+=2) {
        printk(KERN_ALERT "X%-2d: %016llx  X%-2d: %016llx\n", 
               i, regs->regs[i], i+1, regs->regs[i+1]);
    }
    printk(KERN_ALERT "LR : %016llx  SP : %016llx  PC : %016llx\n", 
           regs->regs[30], regs->sp, regs->pc);

    // 简单堆栈回溯
    // dump_stack(); 

    // 重要：为了防止死循环，通常需要禁用断点 -> 单步执行 -> 重新启用
    // 这里为了演示简单，触发一次后我们在日志里打印，然后可能需要用户手动移除或自行处理单步
    // 在真实场景中，你需要在这里修改 regs->pstate 开启单步，或者临时关闭 DBGBCR
    
    return 1; // 返回 1 表示我们处理了这个异常
}

// 2. 汇编操作：在当前 CPU 核心上写入调试寄存器
static void install_hw_bp_on_cpu(void *info) {
    struct _HWBP_INFO *bp = (struct _HWBP_INFO *)info;
    unsigned long addr = bp->addr;
    u32 ctrl;

    // 解锁 OS Lock (允许访问调试寄存器)
    asm volatile("msr oslar_el1, xzr" : : : "memory");
    isb();

    // 写入断点地址到 BVR0 (Breakpoint Value Register 0)
    asm volatile("msr dbgbvr0_el1, %0" : : "r" (addr));

    // 计算控制寄存器 BCR0 的值
    // Bit 0: Enable
    // Bit 1-2: EL1(Kernel) / EL0(User) control. 
    // We target EL0 (0x2) or Both (0x3). Let's use 0x3 to be safe or 0x2 for user only.
    // Bit 5-8: Byte address select (0xf for any byte in word)
    ctrl = (1 << 0) | (3 << 1) | (0xf << 5); 
    
    // 写入控制寄存器
    asm volatile("msr dbgbcr0_el1, %0" : : "r" (ctrl));
    isb();
    
    // printk(KERN_INFO "[Shami] CPU%d: HWBP Installed at %lx\n", smp_processor_id(), addr);
}

// 3. 汇编操作：移除断点
static void uninstall_hw_bp_on_cpu(void *unused) {
    asm volatile("msr oslar_el1, xzr" : : : "memory");
    isb();
    // 写入 0 到控制寄存器禁用断点
    asm volatile("msr dbgbcr0_el1, %0" : : "r" (0));
    isb();
}

// ==========================================
// >>>>>>>>>> IOCTL 修改区域 <<<<<<<<<<
// ==========================================

static long shami_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    struct task_struct *task;
    struct pid *pid_struct;
    struct mm_struct *mm;
    long ret = -EINVAL;
    COPY_MEMORY cm;
    HWBP_INFO bp_info;
    void *kbuf = NULL;
    uintptr_t api_addr = 0;

    // 处理读写内存 (保持原有逻辑)
    if (cmd == OP_READ_MEM || cmd == OP_WRITE_MEM) {
        if (copy_from_user(&cm, (void __user *)arg, sizeof(cm))) return -EFAULT;
        kbuf = kmalloc(cm.size, GFP_KERNEL);
        if (!kbuf) return -ENOMEM;
    }

    switch (cmd) {
        case OP_READ_MEM: 
            // ... (原有代码保持不变) ...
            // 为了节省篇幅，这里略去原有代码，直接引用你的 read_memory_force 逻辑
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
            // ... (原有代码保持不变) ...
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

        // >>> 新增：设置内核 API 地址 <<<
        case OP_SET_API_ADDR:
            if (copy_from_user(&api_addr, (void __user *)arg, sizeof(api_addr))) return -EFAULT;
            // 假设用户传进来的是 hook_debug_fault_code 的地址
            // 在 Android GKI 内核上，你需要先在用户态 grep /proc/kallsyms 找到这个地址传进来
            g_hook_debug_func = (func_hook_debug_fault_code)api_addr;
            printk(KERN_INFO "[Shami] Debug Hook API address set to: %lx\n", api_addr);
            
            // 立即尝试注册我们的回调函数
            // DBG_ESR_EVT_HWBP 通常对应 0x32 (HW Breakpoint Exception Class)
            if (g_hook_debug_func) {
                // 注意：这里 0x30~0x33 都是 debug 相关的 EC，这里我们注册 0
                // 具体的 nr (第一个参数) 取决于内核版本，ARM64 通常 hook DBG_ESR_EVT_HWBP
                // 如果是旧内核可能是 register_debug_fault_handler
                // 这里演示调用 hook_debug_fault_code(DBG_ESR_EVT_HWBP, handler, ...)
                // 34 = DBG_ESR_EVT_HWBP
                g_hook_debug_func(34, my_hw_bp_handler, 0, 0, "shami_bp");
                printk(KERN_INFO "[Shami] Handler registered.\n");
            }
            ret = 0;
            break;

        // >>> 新增：设置硬件断点 <<<
        case OP_SET_HWBP:
            if (copy_from_user(&bp_info, (void __user *)arg, sizeof(bp_info))) return -EFAULT;
            
            // 更新全局配置
            g_bp_info = bp_info;
            
            // 在所有 CPU 核心上执行写入操作
            // 因为线程可能在任意 CPU 上运行，所以必须对所有核心下断点
            get_online_cpus();
            on_each_cpu(install_hw_bp_on_cpu, &g_bp_info, 1);
            put_online_cpus();
            
            printk(KERN_INFO "[Shami] HWBP Set at %lx for PID %d\n", bp_info.addr, bp_info.pid);
            ret = 0;
            break;

        // >>> 新增：删除硬件断点 <<<
        case OP_DEL_HWBP:
            get_online_cpus();
            on_each_cpu(uninstall_hw_bp_on_cpu, NULL, 1);
            put_online_cpus();
            printk(KERN_INFO "[Shami] HWBP Removed.\n");
            ret = 0;
            break;

        default:
            ret = 0;
            break;
    }

    if (kbuf) kfree(kbuf);
    return ret;
}

// --- 驱动注册逻辑 (保持不变) ---
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
    printk(KERN_INFO "[Shami] Driver Loaded with HWBP support.\n");
    return 0;
}

static void __exit shami_exit(void) {
    // 卸载模块前务必清理断点
    on_each_cpu(uninstall_hw_bp_on_cpu, NULL, 1);
    
    device_destroy(shami_class, MKDEV(major, 0));
    class_destroy(shami_class);
    unregister_chrdev(major, DEVICE_NAME);
}

module_init(shami_init);
module_exit(shami_exit);
MODULE_LICENSE("GPL");
