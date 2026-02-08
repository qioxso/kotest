#ifndef COMM_H
#define COMM_H

#ifdef __KERNEL__
    #include <linux/types.h>
#else
    #include <stdint.h>
    #include <sys/types.h>
#endif

// 操作码定义
enum OPERATIONS {
    OP_INIT_KEY = 0x800,
    OP_READ_MEM = 0x801,
    OP_WRITE_MEM = 0x802,
    OP_MODULE_BASE = 0x803,
    OP_SET_API_ADDR = 0x804, // (保留占位，不再使用)
    OP_SET_HWBP = 0x805,     // 设置硬件断点
    OP_DEL_HWBP = 0x806      // 删除硬件断点
};

// 内存拷贝结构体
typedef struct _COPY_MEMORY {
    pid_t pid;
    uintptr_t addr;
    void* buffer;
    size_t size;
} COPY_MEMORY;

// 模块基址结构体
typedef struct _MODULE_BASE {
    pid_t pid;
    char* name;
    uintptr_t base;
} MODULE_BASE;

// 硬件断点配置结构
typedef struct _HWBP_INFO {
    pid_t pid;          // 目标进程 PID
    uintptr_t addr;     // 断点地址
    int enable;         // (未使用)
    int type;           // (未使用，默认 EXECUTE)
} HWBP_INFO;

#endif // COMM_H
