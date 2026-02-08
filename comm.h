// comm.h
#ifndef COMM_H
#define COMM_H

#ifdef __KERNEL__
    #include <linux/types.h>
#else
    #include <stdint.h>
    #include <sys/types.h>
#endif

enum OPERATIONS {
    OP_INIT_KEY = 0x800,
    OP_READ_MEM = 0x801,
    OP_WRITE_MEM = 0x802,
    OP_MODULE_BASE = 0x803,
    OP_SET_API_ADDR = 0x804, // 用于传入内核函数地址 (如 hook_debug_fault_code)
    OP_SET_HWBP = 0x805,     // 新增：设置硬件断点
    OP_DEL_HWBP = 0x806      // 新增：移除硬件断点
};

// ... 原有的 COPY_MEMORY 和 MODULE_BASE 保持不变 ...
typedef struct _COPY_MEMORY {
    pid_t pid;
    uintptr_t addr;
    void* buffer;
    size_t size;
} COPY_MEMORY;

typedef struct _MODULE_BASE {
    pid_t pid;
    char* name;
    uintptr_t base;
} MODULE_BASE;

// 新增：硬件断点配置结构
typedef struct _HWBP_INFO {
    pid_t pid;          // 目标进程 PID (0表示不限制)
    uintptr_t addr;     // 断点地址
    int enable;         // 1=开启, 0=关闭
    int type;           // 0=执行断点(Execute), 1=写断点(Write/Watchpoint)
} HWBP_INFO;

#endif // COMM_H
