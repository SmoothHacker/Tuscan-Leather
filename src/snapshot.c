#include "snapshot.h"

struct snapshot *snapshot;

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

  // Walk bitmap and queue dirty pages for restoration
  const uint64_t NumberBits = 64;
  for (uint64_t QwordIdx = 0; QwordIdx < BITMAP_SIZE_QWORDS; QwordIdx++) {
    const uint64_t DirtyQword = guest->dirty_bitmap[QwordIdx];
    if (DirtyQword == 0) {
      continue;
    }

    for (uint64_t BitIdx = 0; BitIdx < NumberBits; BitIdx++) {
      const uint8_t DirtyBit = (DirtyQword >> BitIdx) & 1;
      if (DirtyBit == 0) {
        continue;
      }
      numOfPages++;
      const uint64_t DirtyPageIdx = (QwordIdx * NumberBits) + BitIdx;
      const uint64_t guestPhysAddr = DirtyPageIdx * PAGE_SIZE;

      // memcpy to restore page
      uint8_t *guestVirtAddr = ((uint8_t *)guest->mem) + guestPhysAddr;
      // Align guestVirtAddr
      // guestVirtAddr = (void *)guestVirtAddr & ~0xfff;

      uint8_t *snapshotVirtAddr = (((uint8_t *)guest->mem) + guestPhysAddr);
      memcpy(guestVirtAddr, snapshotVirtAddr, 0x1000);
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

  gettimeofday(&end, 0);
  printf("[*] Snapshot Restored - Microseconds: %ld\n",
         end.tv_usec - start.tv_usec);

  // Check restore integrity
  int ret;
  if ((ret = memcmp(guest->mem, snapshot->mem, MEM_SIZE)) != 0) {
    printf("Snapshot failed to restore - Bytes off %d\n", ret);
    exit(-1);
  } else {
    printf("Snapshot restore successful\n");
  }
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
