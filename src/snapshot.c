#include "snapshot.h"

struct snapshot *snapshot;

uint64_t countSetBits(uint64_t n) {
  uint64_t count = 0;
  while (n) {
    n &= (n - 1);
    count++;
  }
  return count;
}

/*
 * restoreSnapshot
 * restores a prior saved snapshot of the vm to reset the kernel environment.
 * */
int restoreSnapshot(kernelGuest *guest) {
  struct timeval start, end;

  gettimeofday(&start, 0);
  // Fetch Dirty Log
  struct kvm_dirty_log dirty_log = {
      .slot = 0, // The ID for the kvm memory slot
      .dirty_bitmap = guest->dirty_bitmap,
  };

  if (ioctl(guest->vmfd, KVM_GET_DIRTY_LOG, &dirty_log) < 0)
    err(-1, "[!] Failed to get Dirty Log");

  // Walk Dirty Bitmap
  uint64_t numOfPages = 0;
  for (int i = 0; i < 0x1000; i += 2) {
    if (guest->dirty_bitmap[i] != 0) {
      numOfPages += countSetBits(guest->dirty_bitmap[i]);
    }
  }

  printf("[*] %lu 4k pages need to be reset\n", numOfPages);

  // Clear Dirty Log
  struct kvm_clear_dirty_log ClearDirtyLog = {
      .slot = 0,
      .num_pages = (uint32_t)0x40000,
      .first_page = 0,
      .dirty_bitmap = guest->dirty_bitmap,
  };

  if (ioctl(guest->vmfd, KVM_CLEAR_DIRTY_LOG, &ClearDirtyLog) < 0) {
    err(-1, "[!] Failed to clear the dirty log - restore");
  }

  if (ioctl(guest->vcpu_fd, KVM_SET_SREGS, &snapshot->sregs) < 0)
    err(-1, "[!] Failed to set special registers - restore");

  if (ioctl(guest->vcpu_fd, KVM_SET_REGS, &snapshot->regs) < 0)
    err(-1, "[!] Failed to set registers - restore");

  memcpy(guest->mem, snapshot->mem, MEM_SIZE);
  gettimeofday(&end, 0);
  printf("[*] Snapshot Restored - Micro Seconds: %ld\n",
         end.tv_usec - start.tv_usec);
  return 0;
}

/*
 * createSnapshot
 * Creates a snapshot of the vm and stores it for later use in restoration.
 * */
int createSnapshot(kernelGuest *guest) {
  snapshot = malloc(sizeof(struct snapshot));
  memset(snapshot, 0x0, sizeof(struct snapshot));

  if (ioctl(guest->vcpu_fd, KVM_GET_SREGS, &snapshot->sregs) < 0)
    err(1, "[!] Failed to get special registers");

  if (ioctl(guest->vcpu_fd, KVM_GET_REGS, &snapshot->regs) < 0)
    err(1, "[!] Failed to get registers");

  snapshot->regs.rip += 1; // needed to go past out instruction in ioctl handler
  snapshot->mem = malloc(MEM_SIZE); // Allocate VM memory
  memcpy(snapshot->mem, guest->mem, MEM_SIZE);

  // Get KVM Dirty Log
  struct kvm_dirty_log dirty_log = {
      .slot = 0, // The ID for the only slot in memory
      .dirty_bitmap = guest->dirty_bitmap,
  };
  if (ioctl(guest->vmfd, KVM_GET_DIRTY_LOG, &dirty_log) < 0)
    err(-1, "[!] Failed to get Dirty Log");

  // Clear Dirty Log
  struct kvm_clear_dirty_log ClearDirtyLog = {
      .slot = 0,
      .num_pages = (uint32_t)0x40000,
      .first_page = 0,
      .dirty_bitmap = guest->dirty_bitmap,
  };

  if (ioctl(guest->vmfd, KVM_CLEAR_DIRTY_LOG, &ClearDirtyLog) < 0) {
    perror("KVM_CLEAR_DIRTY_LOG");
  }

  printf("[*] Snapshot Taken\n");
  return 0;
}

uint64_t alignGuestAddr(uint64_t guestAddr) { return guestAddr & ~0xfff; }
