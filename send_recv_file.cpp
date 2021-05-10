#include "function.h"

int recvFile(int sockfd)
{
    // int ret;
    // int dataLen;
    // char buf[1000] = {0};




    return 0;
}

int sendFile(int client_fd, const char *FILENAME)
{
    int ret;
    Packet packet;
    int file_fd = open(FILENAME, O_RDWR);
    ERROR_CHECK(file_fd, -1, "open");

    //传送文件名称
    packet.dataLen = strlen(FILENAME);
    strcpy(packet.buf, FILENAME);
    sendCycle(client_fd, &packet, sizeof(int) + packet.dataLen);

    //传送文件大小
    struct stat statbuf;
    ret = stat(FILENAME, &statbuf);
    ERROR_CHECK(ret, -1, "stat");
    packet.dataLen = sizeof(off_t);
    memcpy(packet.buf, &statbuf.st_size, packet.dataLen);
    sendCycle(client_fd, &packet, sizeof(int) + packet.dataLen);

    //传送文件内容
    //原型: void* mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offsize);
    //返回值: 成功则返回映射区起始地址, 失败则返回MAP_FAILED(-1).
    //参数 :
    //    addr : 指定映射的起始地址, 通常设为NULL, 由系统指定.
    //    length : 将文件的多大长度映射到内存.
    //    prot : 映射区的保护方式, 可以是 :
    //    PROT_EXEC : 映射区可被执行.
    //    PROT_READ : 映射区可被读取.
    //    PROT_WRITE : 映射区可被写入.
    //    PROT_NONE : 映射区不能存取.
    //    flags : 映射区的特性, 可以是 :
    //    MAP_SHARED : 对映射区域的写入数据会复制回文件, 且允许其他映射该文件的进程共享.
    //    MAP_PRIVATE : 对映射区域的写入操作会产生一个映射的复制(copy - on - write), 对此区域所做的修改不会写回原文件.
    //    此外还有其他几个flags不很常用, 具体查看linux C函数说明.
    //    fd : 由open返回的文件描述符, 代表要映射的文件.
    //    offset : 以文件开始处的偏移量, 必须是分页大小的整数倍, 通常为0, 表示从文件头开始映射.
    char *pmap = (char *)mmap(NULL, statbuf.st_size, PROT_READ, MAP_SHARED, file_fd, 0);
    ERROR_CHECK(pmap, (char *)-1, "mmap");
    off_t offset = 0, lastsize = 0;
    off_t slice = statbuf.st_size / 100;
    while (1)
    {
        if (statbuf.st_size > offset + (off_t)sizeof(packet.buf))
        {
            packet.dataLen = sizeof(packet.buf);
            memcpy(packet.buf, pmap + offset, packet.dataLen);
            sendCycle(client_fd, &packet, sizeof(int) + packet.dataLen);
            offset += packet.dataLen;
            //打印
            if (offset - lastsize > slice)
            {
                printf("\r%5.2f%%", (float)offset / statbuf.st_size * 100);
                fflush(stdout);
                lastsize = offset;
            }
        }
        else
        {
            packet.dataLen = statbuf.st_size - offset;
            memcpy(packet.buf, pmap + offset, packet.dataLen);
            sendCycle(client_fd, &packet, sizeof(int) + packet.dataLen);
            break;
        }
    }
    printf("\r100.00%%\n");
    ret = munmap(pmap, statbuf.st_size);
    ERROR_CHECK(ret, -1, "munmap");
    //发送传送结束标志
    packet.dataLen = 0;
    sendCycle(client_fd, &packet, sizeof(int));

    close(file_fd);
    return 0;
}
