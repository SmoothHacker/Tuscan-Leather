#ifndef TUSCAN_LEATHER_SNAPSHOT_H
#define TUSCAN_LEATHER_SNAPSHOT_H

#include <errno.h>
#include <linux/kvm.h>
#include <sys/time.h>

#include "kernelVM.h"

struct snapshot {
  void *mem;
  struct kvm_regs regs;
  struct kvm_sregs sregs;
};

extern struct snapshot *snapshot;

int restoreSnapshot(kernelGuest *guest);
int createSnapshot(kernelGuest *guest);

#endif // TUSCAN_LEATHER_SNAPSHOT_H
