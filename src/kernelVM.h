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
#include <stdlib.h>

#define MAX_CPUID_ENTRIES 100

struct kernelGuest {
    int vmfd;
    int vcpu_fd;
    int kvm_fd;
    void *mem;
};

struct Snapshot {
    void *memSnapshot;
    void *vcpuSnapshot;
};

int createKernelVM(struct kernelGuest *guest);
int loadKernelVM(struct kernelGuest *guest, const char* kernelImagePath, const char* initrdImagePath);
int cleanupKernelVM(struct kernelGuest *guest);
int runKernelVM(struct kernelGuest *guest);
int initVMRegs(struct kernelGuest *guest);
int createCPUID(struct kernelGuest *guest);
int filterCPUID(struct kvm_cpuid2 *cpuid);

#endif //LATEREGISTRATION_KERNELVM_H
