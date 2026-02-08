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
    OP_SET_SWBP = 0x805,     // 改名为 SET_SWBP (软件断点)
    OP_DEL_SWBP = 0x806
};

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

// [修改] 增加 orig_instruction 字段
typedef struct _SWBP_INFO {
    pid_t pid;
    uintptr_t addr;
    uint32_t orig_instruction; // 保存原始的4字节指令
} SWBP_INFO;

#endif // COMM_H
