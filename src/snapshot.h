#ifndef TUSCAN_LEATHER_SNAPSHOT_H
#define TUSCAN_LEATHER_SNAPSHOT_H

#include <errno.h>
#include <linux/kvm.h>

#include "kernelVM.h"

struct snapshot {
  void *mem;
  struct kvm_regs regs;
  struct kvm_sregs sregs;
  struct kvm_irqchip irqchip;
};

extern struct snapshot *snapshot;

int restoreSnapshot(kernelGuest *guest);
int createSnapshot(kernelGuest *guest);
int dumpPageTable(kernelGuest *guest, uint64_t cr3_addr);
int pageTableFeatureEmumeration(kernelGuest *guest);

#endif // TUSCAN_LEATHER_SNAPSHOT_H
