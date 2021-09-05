#ifndef LATEREGISTRATION_KERNELVM_H
#define LATEREGISTRATION_KERNELVM_H

#include <sys/ioctl.h>
#include <linux/kvm.h>
#include <err.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <asm/bootparam.h>
#include <linux/kvm_para.h>

struct kernelGuest {
    int vmfd;
    int vcpu_fd;
    int kvm_fd;
    void *mem;
};

int createKernelVM(struct kernelGuest *guest);
int loadKernelVM(struct kernelGuest *guest, const char* kernelImagePath, const char* initrdImagePath);
int cleanupKernelVM(struct kernelGuest *guest);
int runKernelVM(struct kernelGuest *guest);
int initVMRegs(struct kernelGuest *guest);
int createCPUID(struct kernelGuest *guest);

#endif //LATEREGISTRATION_KERNELVM_H
