#ifndef LATEREGISTRATION_KERNELVM_H
#define LATEREGISTRATION_KERNELVM_H

#include <asm/bootparam.h>
#include <err.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <linux/kvm_para.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define MEM_SIZE 1 << 30
#define BOOT_PARAM_ADDR 0x10000
#define CMDLINE_ADDR 0x20000
#define KERNEL_ADDR 0x100000
#define INITRD_ADDR 0xf000000
#define E820Ram 1
#define E820Reserved 2

#define RealModeIvtBegin 0x00000000
#define EBDAStart 0x0009fc00
#define VGARAMBegin 0x000a0000
#define MBBIOSBegin 0x000f0000
#define MBBIOSEnd 0x000fffff

struct kernelGuest {
  int vmfd;
  int vcpu_fd;
  int kvm_fd;
  void *mem;
  void *initrdMemAddr;
  void *kernelMemAddr;
  struct kvm_run *runStruct;
};

int createKernelVM(struct kernelGuest *guest);

int loadKernelVM(struct kernelGuest *guest, const char *kernelImagePath,
                 const char *initrdImagePath);

int cleanupKernelVM(struct kernelGuest *guest);

int runKernelVM(struct kernelGuest *guest);

int setupKernelVM(struct kernelGuest *guest);

int initVMRegs(struct kernelGuest *guest);

int createCPUID(struct kernelGuest *guest);

int filterCPUID(struct kvm_cpuid2 *cpuid);

int addE820Entry(struct boot_params *boot, uint64_t addr, uint64_t size,
                 uint32_t type);

#endif // LATEREGISTRATION_KERNELVM_H
