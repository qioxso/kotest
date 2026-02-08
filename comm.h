#ifndef COMM_H
#define COMM_H

#ifdef __KERNEL__
    #include <linux/types.h>
#else
    #include <stdint.h>
    #include <sys/types.h>
#endif

enum OPERATIONS {
    OP_READ_MEM = 0x801,
    OP_WRITE_MEM = 0x802,
    OP_SET_SWBP = 0x805,     // 设置软件断点
    OP_DEL_SWBP = 0x806      // 删除软件断点
};

typedef struct _COPY_MEMORY {
    pid_t pid;
    uintptr_t addr;
    void* buffer;
    size_t size;
} COPY_MEMORY;

typedef struct _SWBP_INFO {
    pid_t pid;
    uintptr_t addr;
    uint32_t orig_instruction; // 原始指令
} SWBP_INFO;

#endif // COMM_H
