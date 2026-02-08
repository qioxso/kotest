// comm.h
#ifndef COMM_H
#define COMM_H

// 根据编译环境自动选择头文件
#ifdef __KERNEL__
    #include <linux/types.h>
#else
    #include <stdint.h>
    #include <sys/types.h>
#endif

// 操作码定义
enum OPERATIONS {
    OP_INIT_KEY    = 0x800,
    OP_READ_MEM    = 0x801,
    OP_WRITE_MEM   = 0x802,
    OP_MODULE_BASE = 0x803,
    OP_SET_API_ADDR= 0x804,
    // 新增 Uprobe 功能
    OP_ADD_UPROBE  = 0x805,
    OP_DEL_UPROBE  = 0x806
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

// 新增：断点配置结构体
typedef struct _UPROBE_CONFIG {
    pid_t pid;      // 目标进程PID
    uintptr_t addr; // 目标虚拟地址
} UPROBE_CONFIG;

#endif // COMM_H
