#ifndef LATEREGISTRATION_SNAPSHOT_H
#define LATEREGISTRATION_SNAPSHOT_H

#include <linux/kvm.h>
#include "kernelVM.h"

struct Snapshot {
    void *mem;
    struct kvm_regs regs;
    struct kvm_sregs sregs;
    struct kvm_irqchip irqchip;
};

extern struct Snapshot *snapshot;

int restoreSnapshot(struct kernelGuest *guest);
int createSnapshot(struct kernelGuest *guest);

#endif //LATEREGISTRATION_SNAPSHOT_H
