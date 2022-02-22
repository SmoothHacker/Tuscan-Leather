#ifndef TUSCAN_LEATHER_SNAPSHOT_H
#define TUSCAN_LEATHER_SNAPSHOT_H

#include <errno.h>
#include <linux/kvm.h>

#include "kernelVM.h"

#define MAX_PML4_ENTRIES 512

union pml4_entry {
  uint64_t bitmap;
  struct {
    uint8_t present : 1;
    uint8_t readWrite : 1;
    uint8_t userSuprevisor : 1;
    uint8_t pageLevelWriteThrough : 1;
    uint8_t pageLevelCacheDisable : 1;
    uint8_t accessed : 1;
    uint8_t ignored : 6; // double check for accuracy
    uint8_t restart : 1; // Bit 11 for HLAT paging
    uint64_t pageDirPtrTable : 35;
  } bits;
};

struct snapshot {
  void *mem;
  struct kvm_regs regs;
  struct kvm_sregs sregs;
};

extern struct snapshot *snapshot;

int restoreSnapshot(kernelGuest *guest);
int createSnapshot(kernelGuest *guest);
uint64_t alignGuestAddr(uint64_t guestAddr);
int iteratePageTables(kernelGuest *guest, uint64_t cr3_addr);
int pageTableFeatureEnumeration(kernelGuest *guest);

#endif // TUSCAN_LEATHER_SNAPSHOT_H
