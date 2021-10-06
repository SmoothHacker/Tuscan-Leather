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

#define MEM_SIZE 1 << 30
#define BOOT_PARAM_ADDR 0x10000
#define CMDLINE_ADDR 0x20000
#define KERNEL_ADDR 0x100000
#define INITRD_ADDR 0xf000000
#define EddMbrSigMax 16
#define E820Ram 1
#define E820Reserved 2

#define RealModeIvtBegin 0x00000000
#define EBDAStart        0x0009fc00
#define VGARAMBegin      0x000a0000
#define MBBIOSBegin      0x000f0000
#define MBBIOSEnd        0x000fffff

#define BOOT_PROTOCOL_REQUIRED 0x206

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
int setupKernelVM(struct kernelGuest *guest);
int initVMRegs(struct kernelGuest *guest);
int createCPUID(struct kernelGuest *guest);
int filterCPUID(struct kvm_cpuid2 *cpuid);
int addE820Entry(struct boot_params* boot, uint64_t addr, uint64_t size, uint32_t type);
int dumpRegisters(struct kernelGuest *guest);

#endif //LATEREGISTRATION_KERNELVM_H
