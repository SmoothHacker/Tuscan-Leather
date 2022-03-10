#ifndef TUSCAN_LEATHER_KERNELVM_H
#define TUSCAN_LEATHER_KERNELVM_H

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
#include <sys/uio.h>
#include <pthread.h>
#include <x86intrin.h>

#define MEM_SIZE 1 << 30
#define BITMAP_SIZE_QWORDS 0x1000
#define BITMAP_SIZE_BITS 0x40000
#define PAGE_SIZE 0x1000

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

// KVM Constants - not supported in kernel 5.4
#define KVM_DIRTY_LOG_MANUAL_PROTECT_ENABLE (1 << 0)

extern pthread_mutex_t mutex;
extern pthread_cond_t cond;
extern pthread_mutex_t cyc_reset_mutex;

typedef struct {
  uint64_t cycles_run;
  uint64_t cycles_reset;
  uint64_t cycles_vmexit;
} statistics;

typedef struct {
  int vmfd;
  int vcpu_fd;
  int kvm_fd;
  void *mem;
  void *initrdMemAddr;
  void *kernelMemAddr;
  uint64_t *dirty_bitmap;
  statistics *stats;
} kernelGuest;

int createKernelVM(kernelGuest *guest);
int loadKernelVM(kernelGuest *guest, const char *kernelImagePath,
                 const char *initrdImagePath);
int cleanupKernelVM(kernelGuest *guest);
int runKernelVM(kernelGuest *guest);
int initVMRegs(kernelGuest *guest);
int createCPUID(kernelGuest *guest);
int filterCPUID(struct kvm_cpuid2 *cpuid);
int addE820Entry(struct boot_params *boot, uint64_t addr, uint64_t size,
                 uint32_t type);
int dumpVCPURegs(kernelGuest *guest);
int enableDebug(kernelGuest *guest);

#endif // TUSCAN_LEATHER_KERNELVM_H
