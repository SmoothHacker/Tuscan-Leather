#include "snapshot.h"
#include <sys/time.h>

struct snapshot *snapshot;

/*
 * restoreSnapshot
 * restores a prior saved snapshot of the vm to reset the kernel environment.
 * */
int restoreSnapshot(kernelGuest *guest) {
  struct timeval start, stop;
  double secs = 0;

  gettimeofday(&start, NULL);

  if (ioctl(guest->vcpu_fd, KVM_SET_SREGS, &snapshot->sregs) < 0)
    err(-1, "[!] Failed to set special registers - snapshot");

  if (ioctl(guest->vcpu_fd, KVM_SET_REGS, &snapshot->regs) < 0)
    err(-1, "[!] Failed to set registers - snapshot");

  memcpy(guest->mem, snapshot->mem, MEM_SIZE);
  printf("[*] Snapshot Restored");
  return 0;
}

/*
 * createSnapshot
 * Creates a snapshot of the vm and stores it for later use in restoration.
 * */
int createSnapshot(kernelGuest *guest) {
  struct timeval start, stop;
  double secs = 0;

  gettimeofday(&start, NULL);
  snapshot = malloc(sizeof(struct snapshot));
  memset(snapshot, 0x0, sizeof(struct snapshot));

  if (ioctl(guest->vcpu_fd, KVM_GET_SREGS, &snapshot->sregs) < 0)
    err(1, "[!] Failed to get special registers");

  if (ioctl(guest->vcpu_fd, KVM_GET_REGS, &snapshot->regs) < 0)
    err(1, "[!] Failed to get registers");

  snapshot->regs.rip += 1; // needed to go past out instruction in ioctl handler
  snapshot->mem = malloc(MEM_SIZE); // Allocate VM memory
  memcpy(snapshot->mem, guest->mem, MEM_SIZE);

  gettimeofday(&stop, NULL);
  secs = (double)(stop.tv_usec - start.tv_usec) / 1000000 +
         (double)(stop.tv_sec - start.tv_sec);
  printf("[*] snapshot - time taken %f\n", secs);
  return 0;
}

uint64_t alignGuestAddr(uint64_t guestAddr) { return guestAddr & ~0xfff; }

int pageTableFeatureEnumeration(kernelGuest *guest) {
  struct kvm_sregs *sregs = malloc(sizeof(struct kvm_sregs));
  struct kvm_msrs *msrs =
      malloc(sizeof(struct kvm_msrs) + sizeof(struct kvm_msr_entry));

  if (ioctl(guest->vcpu_fd, KVM_GET_SREGS, sregs) < 0)
    err(-1, "[!] Cannot get sregs\n");

  printf("cr3 0x%llx\n", sregs->cr3);

  // Can grab valid list of known MSRS to retrieve via KVM_GET_MSRS
  msrs->nmsrs = 1;
  msrs->entries[0].index = 0xc0000080; // Address for the IA32_EFER MSR
  if (ioctl(guest->vcpu_fd, KVM_GET_MSRS, msrs) < 0)
    err(-1, "[!] Cannot get IA32_EFER MSR");

  if (sregs->cr4 & (1 << 17))
    printf("[*] PCID is enabled\n");
  else {
    printf("[!] PCID is disabled. Not supported");
    exit(-1);
  }

  if ((sregs->cr0 & (1 << 31)) && (sregs->cr4 & (1 << 5))) {
    // Check bit 8 of the IA32_EFER MSR
    if (msrs->entries[0].data & (1 << 8)) {
      // Check CR4.LA57
      if (sregs->cr4 & (1 << 12)) {
        printf("[*] 5 Level Paging is used\n");
        printf("[!] 5 Level Paging is not supported\n");
        exit(-1);
      } else {
        printf("[*] 4 Level Paging is used\n");
      }
    } else {
      printf("[*] PAE Paging is used\n");
      printf("[!] 4 Level Paging is not supported");
      exit(-1);
    }
  }
  free(sregs);
  free(msrs);
  return 0;
}

int iteratePageTables(kernelGuest *guest, uint64_t cr3_addr) {
  // 4 Level Paging is only supported. Assumption of 46 physical bits and 48
  // virtual bits
  uint64_t pml4eAddr = (cr3_addr & 0xffffffffff000) >> 12;
  uint64_t *pml4e_table = (uint64_t *)(((uint64_t *)guest->mem) + pml4eAddr);

  int numOfPML4Es = 0;
  int writeablePages = 0;
  for (int i = 0; i < MAX_PML4_ENTRIES; i++) {
    union pml4_entry entry;
    entry.bitmap = pml4e_table[i];

    if (entry.bits.present)
      numOfPML4Es++;
    else
      break;

    if (entry.bits.readWrite)
      writeablePages++;
  }

  printf("[*] %d PML4Es\n[*] %d Writeable Pages\n", numOfPML4Es,
         writeablePages);

  return 0;
}
