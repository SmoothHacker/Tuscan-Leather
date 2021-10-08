#include "Snapshot.h"

struct Snapshot *snapshot;

int restoreSnapshot(struct kernelGuest *guest) {
    return 0;
}

int createSnapshot(struct kernelGuest *guest) {
    snapshot = calloc(1, sizeof(struct Snapshot));

    if (ioctl(guest->vcpu_fd, KVM_GET_SREGS, &snapshot->sregs) < 0)
        err(1, "[!] Failed to get special registers");

    if (ioctl(guest->vcpu_fd, KVM_GET_REGS, &snapshot->regs) < 0)
        err(1, "[!] Failed to get registers");

    // clear breakpoint
    snapshot->mem = malloc(MEM_SIZE); // Allocate VM memory
    memcpy(snapshot->mem, guest->mem, MEM_SIZE);
    return 0;
}
