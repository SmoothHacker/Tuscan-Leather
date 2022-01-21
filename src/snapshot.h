#ifndef TUSCAN_LEATHER_SNAPSHOT_H
#define TUSCAN_LEATHER_SNAPSHOT_H

#include <linux/kvm.h>
#include "kernelVM.h"

struct snapshot {
  void *mem;
  struct kvm_regs regs;
  struct kvm_sregs sregs;
  struct kvm_irqchip irqchip;
};

extern struct snapshot *snapshot;

int restoreSnapshot(struct kernelGuest *guest);
int createSnapshot(struct kernelGuest *guest);

#endif // TUSCAN_LEATHER_SNAPSHOT_H
