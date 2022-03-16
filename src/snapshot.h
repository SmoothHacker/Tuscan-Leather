#ifndef TUSCAN_LEATHER_SNAPSHOT_H
#define TUSCAN_LEATHER_SNAPSHOT_H

#include <errno.h>
#include <linux/kvm.h>
#include <sys/time.h>

#include "kernelVM.h"

#define NUMBER_OF_BITS 64

struct snapshot {
  void *mem;
  struct kvm_regs regs;
  struct kvm_sregs sregs;
};

int restoreSnapshot(kernelGuest *guest);
int createSnapshot(kernelGuest *guest);

#endif // TUSCAN_LEATHER_SNAPSHOT_H
