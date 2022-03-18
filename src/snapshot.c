#include "snapshot.h"

/*
 * restoreSnapshot
 * restores a prior saved snapshot of the vm to reset the kernel environment.
 * */
int restoreSnapshot(kernelGuest *guest) {
  struct snapshot *snapshot = guest->snapshot;
  if (ioctl(guest->vcpu_fd, KVM_KVMCLOCK_CTRL) < 0)
    ERR("Unable to set KVMCLOCK_CTRL");

  // Fetch Dirty Log
  struct kvm_dirty_log dirty_log = {
      .slot = 0, // The ID for the kvm memory slot
      .dirty_bitmap = guest->dirty_bitmap,
  };

  if (ioctl(guest->vmfd, KVM_GET_DIRTY_LOG, &dirty_log) < 0)
    ERR("Failed to get Dirty Log");

  int numOfPagesReset = 0;

  // Walk bitmap and queue dirty pages for restoration
  for (uint64_t QwordIdx = 0; QwordIdx < BITMAP_SIZE_QWORDS; QwordIdx++) {
    const uint64_t DirtyQword = guest->dirty_bitmap[QwordIdx];
    if (DirtyQword == 0) {
      continue;
    }

    for (uint64_t BitIdx = 0; BitIdx < NUMBER_OF_BITS; BitIdx++) {
      const uint8_t DirtyBit = (DirtyQword >> BitIdx) & 1;
      if (DirtyBit == 0) {
        continue;
      }

      const uint64_t DirtyPageIdx = (QwordIdx * NUMBER_OF_BITS) + BitIdx;
      const uint64_t guestPhysAddr = DirtyPageIdx * PAGE_SIZE;

      numOfPagesReset++;
      // memcpy to restore page
      void *guestVirtAddr = ((void *)guest->mem) + guestPhysAddr;
      void *snapshotVirtAddr = ((void *)snapshot->mem) + guestPhysAddr;

      memcpy(guestVirtAddr, snapshotVirtAddr, PAGE_SIZE);
    }
  }

  // Clear Dirty Log
  struct kvm_clear_dirty_log ClearDirtyLog = {
      .slot = 0,
      .num_pages = (uint32_t)0x40000,
      .first_page = 0,
      .dirty_bitmap = guest->dirty_bitmap,
  };

  if (ioctl(guest->vmfd, KVM_CLEAR_DIRTY_LOG, &ClearDirtyLog) < 0)
    ERR("Failed to clear the dirty log - restore");

  if (ioctl(guest->vcpu_fd, KVM_SET_SREGS, &snapshot->sregs) < 0)
    ERR("Failed to set special registers - restore");

  if (ioctl(guest->vcpu_fd, KVM_SET_REGS, &snapshot->regs) < 0)
    ERR("Failed to set registers - restore");

  return numOfPagesReset;
}

/*
 * createSnapshot
 * Creates a snapshot of the vm and stores it for later use in restoration.
 * */
int createSnapshot(kernelGuest *guest) {
  if (ioctl(guest->vcpu_fd, KVM_KVMCLOCK_CTRL) < 0)
    ERR("Unable to set KVMCLOCK_CTRL");

  struct snapshot *snapshot = malloc(sizeof(struct snapshot));
  memset(snapshot, 0x0, sizeof(struct snapshot));

  guest->snapshot = snapshot;

  if (ioctl(guest->vcpu_fd, KVM_GET_SREGS, &snapshot->sregs) < 0)
    ERR("Failed to get special registers");

  if (ioctl(guest->vcpu_fd, KVM_GET_REGS, &snapshot->regs) < 0)
    ERR("Failed to get registers");

  snapshot->regs.rip += 1; // needed to go past out instruction in ioctl handler
  snapshot->mem = malloc(MEM_SIZE); // Allocate VM memory
  memcpy(snapshot->mem, guest->mem, MEM_SIZE);

  // Get KVM Dirty Log
  struct kvm_dirty_log dirty_log = {
      .slot = 0, // The ID for the only slot in memory
      .dirty_bitmap = guest->dirty_bitmap,
  };
  if (ioctl(guest->vmfd, KVM_GET_DIRTY_LOG, &dirty_log) < 0)
    ERR("Failed to get Dirty Log");

  // Clear Dirty Log
  struct kvm_clear_dirty_log ClearDirtyLog = {
      .slot = 0,
      .num_pages = (uint32_t)0x40000,
      .first_page = 0,
      .dirty_bitmap = guest->dirty_bitmap,
  };

  if (ioctl(guest->vmfd, KVM_CLEAR_DIRTY_LOG, &ClearDirtyLog) < 0) {
    ERR("KVM_CLEAR_DIRTY_LOG");
  }

  return 0;
}

