#include <string.h>

#include "../os-handler/fuzzRunner.h"
#include "snapshot.h"

int createKernelVM(kernelGuest *guest) {
  if ((guest->vmfd = ioctl(guest->kvm_fd, KVM_CREATE_VM, 0)) < 0)
    err(1, "[!] VM creation failed");

  if (ioctl(guest->kvm_fd, KVM_CHECK_EXTENSION,
            KVM_CAP_MANUAL_DIRTY_LOG_PROTECT2) < 0)
    err(1, "[!] KVM_CAP_MANUAL_DIRTY_LOG_PROTECT2 is not supported");

  struct kvm_enable_cap cap = {.cap = KVM_CAP_MANUAL_DIRTY_LOG_PROTECT2,
                               .args = KVM_DIRTY_LOG_MANUAL_PROTECT_ENABLE};
  if (ioctl(guest->vmfd, KVM_ENABLE_CAP, &cap) < 0)
    err(1, "[!] Enable cap KVM_CAP_MANUAL_DIRTY_LOG_PROTECT2 failed");

  if (ioctl(guest->vmfd, KVM_SET_TSS_ADDR, 0xfffbd000) < 0)
    err(1, "[!] Failed to set TSS addr");

  uint64_t map_addr = 0xffffc000;
  if (ioctl(guest->vmfd, KVM_SET_IDENTITY_MAP_ADDR, &map_addr) < 0)
    err(1, "[!] Failed to set identity map addr");

  if (ioctl(guest->vmfd, KVM_CREATE_IRQCHIP, 0) < 0)
    err(1, "[!] Failed to create irq chip");

  struct kvm_pit_config pit = {.flags = 0};
  if (ioctl(guest->vmfd, KVM_CREATE_PIT2, &pit) < 0)
    err(1, "[!] Failed to create i8254 interval timer");

  guest->mem = mmap(NULL, MEM_SIZE, PROT_READ | PROT_WRITE,
                    MAP_SHARED | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);

  if (!guest->mem)
    err(1, "[!] Failed to mmap VM memory");

  madvise(guest->mem, MEM_SIZE, MADV_MERGEABLE);

  struct kvm_userspace_memory_region region = {.slot = 0,
                                               .flags = KVM_MEM_LOG_DIRTY_PAGES,
                                               .guest_phys_addr = 0,
                                               .memory_size = MEM_SIZE,
                                               .userspace_addr =
                                                   (uint64_t)guest->mem};

  if (ioctl(guest->vmfd, KVM_SET_USER_MEMORY_REGION, &region) < 0)
    err(1, "[!] Failed to set user memory region");

  guest->vcpu_fd = ioctl(guest->vmfd, KVM_CREATE_VCPU, 0);
  if (guest->vcpu_fd < 0)
    err(1, "[!] Failed to create vcpu");

  // Enabling dirty_log tracking
  guest->dirty_bitmap = malloc(BITMAP_SIZE_BITS); // Tracking for 1GB vm memory

  initVMRegs(guest);
  createCPUID(guest);
  return 0;
}

/*
 * loadKernelVM
 * Opens bzImage and initrd and reads them into their proper memory locations.
 * This is also where we set up the boot parameters in accordance with the
 * linux x86 boot protocol and inform the kernel of the memory locations
 * via e820 entries.
 * */
int loadKernelVM(kernelGuest *guest, const char *kernelImagePath,
                 const char *initrdImagePath) {
  int kernelFD = open(kernelImagePath, O_RDONLY);
  int initrdFD = open(initrdImagePath, O_RDONLY);

  // TODO Make this configurable at runtime
  const char *kernelCmdline = "nokaslr quiet console=ttyS0 root=/dev/vda";

  if ((kernelFD == -1) || (initrdFD == -1)) {
    err(1, "[!] Cannot open kernel image and/or initrd");
  }

  struct stat st;
  fstat(kernelFD, &st);
  size_t kernelFileSize = st.st_size;
  void *kernelFile =
      mmap(0, kernelFileSize, PROT_READ | PROT_WRITE, MAP_PRIVATE, kernelFD, 0);
  close(kernelFD);

  fstat(initrdFD, &st);
  size_t initrdFileSize = st.st_size;
  void *initrdFile =
      mmap(0, initrdFileSize, PROT_READ | PROT_WRITE, MAP_PRIVATE, initrdFD, 0);
  close(initrdFD);

  // Setup initrd
  guest->initrdMemAddr = (void *)(((uint8_t *)guest->mem) + INITRD_ADDR);
  memset(guest->initrdMemAddr, 0, initrdFileSize);
  memmove(guest->initrdMemAddr, initrdFile, initrdFileSize);

  // Setup boot loader, cmdline, and kernel
  struct boot_params *boot =
      (struct boot_params *)(((uint8_t *)guest->mem) + BOOT_PARAM_ADDR);
  void *cmdline = (void *)(((uint8_t *)guest->mem) + CMDLINE_ADDR);
  guest->kernelMemAddr = (void *)(((uint8_t *)guest->mem) + KERNEL_ADDR);

  memset(boot, 0, sizeof(struct boot_params));
  memmove(boot, kernelFile, sizeof(struct boot_params));
  size_t offset = (boot->hdr.setup_sects + 1) * 512;
  boot->hdr.vid_mode = 0xfff; // VGA
  boot->hdr.type_of_loader = 0xff;
  boot->hdr.ramdisk_image = INITRD_ADDR;
  boot->hdr.ramdisk_size = initrdFileSize;
  boot->hdr.loadflags |=
      CAN_USE_HEAP | LOADED_HIGH | KEEP_SEGMENTS; // | 0x01 | KEEP_SEGMENTS;
  boot->hdr.heap_end_ptr = 0xFE00;
  boot->hdr.cmd_line_ptr = CMDLINE_ADDR;
  boot->hdr.cmdline_size = strlen(kernelCmdline);
  memset(cmdline, 0, boot->hdr.cmdline_size);
  memcpy(cmdline, kernelCmdline, strlen(kernelCmdline));
  memmove(guest->kernelMemAddr, (char *)kernelFile + offset,
          kernelFileSize - offset);

  // Setup E820Entries
  addE820Entry(boot, RealModeIvtBegin, EBDAStart - RealModeIvtBegin, E820Ram);
  addE820Entry(boot, EBDAStart, VGARAMBegin - EBDAStart, E820Reserved);
  addE820Entry(boot, MBBIOSBegin, MBBIOSEnd - MBBIOSBegin, E820Reserved);
  addE820Entry(boot, KERNEL_ADDR, (MEM_SIZE)-KERNEL_ADDR, E820Ram);
  return 0;
}

int addE820Entry(struct boot_params *boot, uint64_t addr, uint64_t size,
                 uint32_t type) {
  size_t i = boot->e820_entries;
  boot->e820_table[i] = (struct boot_e820_entry){
      .addr = addr,
      .size = size,
      .type = type,
  };
  boot->e820_entries = i + 1;
  return 0;
}

int cleanupKernelVM(kernelGuest *guest) {
  close(guest->vcpu_fd);
  close(guest->vmfd);
  close(guest->kvm_fd);
  free(guest->dirty_bitmap);
  munmap(guest->mem, 1 << 30);
  return 0;
}

int enableDebug(kernelGuest *guest) {
  /* For some reason the alternative_instructions function in the kernel is
   * triggered cause an interrupt. Don't know a way to resolve and proceed
   */
  struct kvm_guest_debug debug = {
      .control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP,
  };

  if (ioctl(guest->vcpu_fd, KVM_SET_GUEST_DEBUG, &debug) < 0)
    perror("[!] KVM_SET_GUEST_DEBUG failed");

  return 0;
}

/*
 * runKernelVM
 * The main execution loop for the VM.
 * */
int runKernelVM(kernelGuest *guest) {
  int run_size = ioctl(guest->kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
  struct kvm_run *run =
      mmap(0, run_size, PROT_READ | PROT_WRITE, MAP_SHARED, guest->vcpu_fd, 0);

  for (;;) {
    int ret = ioctl(guest->vcpu_fd, KVM_RUN, 0);
    if (ret < 0) {
      err(1, "kvm_run failed");
    }

    switch (run->exit_reason) {
    case KVM_EXIT_IO: // TODO: Add system for ttys to be sent to stdout.
      switch (run->io.port) {
      case 0x3f8:
        if (run->io.direction == KVM_EXIT_IO_OUT)
          write(STDOUT_FILENO, (char *)run + run->io.data_offset, 1);
        break;
      case 0x3fd:
        if (run->io.direction == KVM_EXIT_IO_IN)
          *((char *)run + run->io.data_offset) =
              0x20; // for console input to be replaced by emulation framework
        break;
      case 0xdead: // Port Reserved by os-handler kernel module
        if (run->io.direction == KVM_EXIT_IO_OUT) {
          uint8_t *ioctl_cmd = (uint8_t *)run + run->io.data_offset;

          switch (*ioctl_cmd) {
          case TAKE_SNAPSHOT:
            printf("[*] Taking snapshot\n");
            createSnapshot(guest);
            break;
          case RESTORE_VM:
            // printf("[*] Restoring snapshot\n");
            restoreSnapshot(guest);
            break;
          case ENABLE_DEBUG:
            enableDebug(guest);
            break;
          default:
            printf("[!] Unknown ioctl command from os-handler: %d\n",
                   *ioctl_cmd);
            break;
          }
        }
        break;
      default:
        break;
      }
      break;
    case KVM_EXIT_HLT:
      printf("\n\t[!] Encountered HLT instruction\n\n");
      dumpVCPURegs(guest);
      exit(-1);
    case KVM_EXIT_FAIL_ENTRY:
      err(1, "[!] FAIL_ENTRY: hw bits failure reason: 0x%llx\n",
          run->fail_entry.hardware_entry_failure_reason);
    case KVM_EXIT_SHUTDOWN:
      printf("[!] Shutdown Received\n");
      return 0;
    case KVM_EXIT_DEBUG:
      printf("[!] Encountered Debug event\n");
      dumpVCPURegs(guest);
      exit(-1);
    default:
      printf("[!] Unknown Exit Reason: %d\n", run->exit_reason);
      return -1;
    }
  }
}

/*
 * initVMRegs
 * Sets up registers for the VM.
 * Sourced from the Linux x86 boot protocol.
 * */
int initVMRegs(kernelGuest *guest) {
  struct kvm_regs regs;
  struct kvm_sregs sregs;
  if (ioctl(guest->vcpu_fd, KVM_GET_SREGS, &sregs) < 0)
    err(1, "[!] Failed to get special registers");

  sregs.cs.base = 0;
  sregs.cs.limit = ~0;
  sregs.cs.g = 1;

  sregs.ds.base = 0;
  sregs.ds.limit = ~0;
  sregs.ds.g = 1;

  sregs.fs.base = 0;
  sregs.fs.limit = ~0;
  sregs.fs.g = 1;

  sregs.gs.base = 0;
  sregs.gs.limit = ~0;
  sregs.gs.g = 1;

  sregs.es.base = 0;
  sregs.es.limit = ~0;
  sregs.es.g = 1;

  sregs.ss.base = 0;
  sregs.ss.limit = ~0;
  sregs.ss.g = 1;

  sregs.cs.db = 1;
  sregs.ss.db = 1;
  sregs.cr0 |= 1; // enable protected mode

  if (ioctl(guest->vcpu_fd, KVM_SET_SREGS, &sregs) < 0)
    err(1, "[!] Failed to set special registers");

  if (ioctl(guest->vcpu_fd, KVM_GET_REGS, &regs) < 0)
    err(1, "[!] Failed to get registers");

  regs = (struct kvm_regs){
      .rflags = 2,
      .rip = KERNEL_ADDR,
      .rsi = BOOT_PARAM_ADDR,
  };

  if (ioctl(guest->vcpu_fd, KVM_SET_REGS, &regs) < 0)
    err(1, "[!] Failed to set registers");
  return 0;
}

/*
 * createCPUID
 * Set up the CPUID instruction for linux to recognize this harness as KVM and
 * what processor features are available to the operating system.
 * */
int createCPUID(kernelGuest *guest) {
  struct kvm_cpuid2 *kvm_cpuid;

  kvm_cpuid = calloc(1, sizeof(*kvm_cpuid) + 100 * sizeof(*kvm_cpuid->entries));

  kvm_cpuid->nent = 100;
  if (ioctl(guest->kvm_fd, KVM_GET_SUPPORTED_CPUID, kvm_cpuid) < 0)
    err(1, "[!] KVM_GET_SUPPORTED_CPUID failed");

  filterCPUID(kvm_cpuid);

  if (ioctl(guest->vcpu_fd, KVM_SET_CPUID2, kvm_cpuid) < 0)
    err(1, "[!] KVM_SET_CPUID2 failed");

  free(kvm_cpuid);
  return 0;
}

int filterCPUID(struct kvm_cpuid2 *cpuid) {
  // Remove CPUID functions that are not supported by Tuscan-Leather
  for (unsigned int i = 0; i < cpuid->nent; i++) {
    struct kvm_cpuid_entry2 *entry = &cpuid->entries[i];

    switch (entry->function) {
    case KVM_CPUID_FEATURES:
      // Vendor name
      entry->eax = KVM_CPUID_FEATURES;
      entry->ebx = 0x4b4d564b;
      entry->ecx = 0x564b4d56;
      entry->edx = 0x4d;
      break;
    case 1:
      // Set X86_FEATURE_HYPERVISOR
      if (entry->index == 0)
        entry->ecx |= (1 << 31);
      break;
    case 6:
      // Clear X86_FEATURE_EPB
      entry->ecx = entry->ecx & ~(1 << 3);
      break;
    case 10: { // Architectural Performance Monitoring
      union cpuid10_eax {
        struct {
          unsigned int version_id : 8;
          unsigned int num_counters : 8;
          unsigned int bit_width : 8;
          unsigned int mask_length : 8;
        } split;
        unsigned int full;
      } eax;

      /*
       * If the host has perf system running,
       * but no architectural events available
       * through kvm pmu -- disable perf support,
       * thus guest won't even try to access msr
       * registers.
       */
      if (entry->eax) {
        eax.full = entry->eax;
        if (eax.split.version_id != 2u || !eax.split.num_counters)
          entry->eax = 0;
      }
      break;
    }
    default:
      // Keep the CPUID function as -is
      break;
    }
  }
  return 0;
}

int dumpVCPURegs(kernelGuest *guest) {
  struct kvm_regs regs;
  if (ioctl(guest->vcpu_fd, KVM_GET_REGS, &regs) < 0)
    err(1, "[!] Failed to get registers - dumpVCPURegs");

  printf("[*] Register Dump\n");
  printf("[*] rax: 0x%016llx\n", regs.rax);
  printf("[*] rbx: 0x%016llx\n", regs.rbx);
  printf("[*] rcx: 0x%016llx\n", regs.rcx);
  printf("[*] rdx: 0x%016llx\n", regs.rdx);
  printf("[*] rsp: 0x%016llx\n", regs.rsp);
  printf("[*] rbp: 0x%016llx\n", regs.rbp);
  printf("[*] rsi: 0x%016llx\n", regs.rsi);
  printf("[*] rdi: 0x%016llx\n", regs.rdi);
  printf("[*] rip: 0x%016llx\n", regs.rip);
  printf("[*] r8:  0x%016llx\n", regs.r8);
  printf("[*] r9:  0x%016llx\n", regs.r9);
  printf("[*] r10: 0x%016llx\n", regs.r10);
  printf("[*] r11: 0x%016llx\n", regs.r11);
  printf("[*] r12: 0x%016llx\n", regs.r12);
  printf("[*] r13: 0x%016llx\n", regs.r13);
  printf("[*] r14: 0x%016llx\n", regs.r14);
  printf("[*] r15: 0x%016llx\n", regs.r15);

  return 0;
}
