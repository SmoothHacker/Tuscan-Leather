#ifndef TUSCAN_LEATHER_KERNELVM_H
#define TUSCAN_LEATHER_KERNELVM_H

#include <asm/bootparam.h>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <err.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <linux/kvm_para.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>
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

#define ERR(s) err(-1, "[!] " s)

// Have to modify everytime we re-compile the kernel
#define KASAN_REPORT_COLD 0xffffffff83755621

typedef struct {
  uint64_t cycles_run;
  uint64_t cycles_reset;
  uint64_t cycles_vmexit;
  uint64_t cases;
  uint64_t numOfPagesReset;
  uint64_t totalPCs;
  pthread_mutex_t *lock;
} statistics;

typedef struct {
  int vmfd;
  int vcpu_fd;
  int kvm_fd;
  void *mem;
  void *initrdMemAddr;
  void *kernelMemAddr;
  uint64_t *dirty_bitmap;
  uint64_t pcs;
  statistics *stats;
  struct snapshot *snapshot;
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
