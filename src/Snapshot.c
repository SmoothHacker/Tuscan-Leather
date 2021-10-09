#include "Snapshot.h"

#include <sys/time.h>

struct Snapshot *snapshot;

int restoreSnapshot(struct kernelGuest *guest) { return 0; }

int createSnapshot(struct kernelGuest *guest) {
  struct timeval start, stop;
  double secs = 0;

  gettimeofday(&start, NULL);

  snapshot = calloc(1, sizeof(struct Snapshot));

  if (ioctl(guest->vcpu_fd, KVM_GET_SREGS, &snapshot->sregs) < 0)
    err(1, "[!] Failed to get special registers");

  if (ioctl(guest->vcpu_fd, KVM_GET_REGS, &snapshot->regs) < 0)
    err(1, "[!] Failed to get registers");

  // clear breakpoint
  snapshot->mem = malloc(MEM_SIZE); // Allocate VM memory
  memcpy(snapshot->mem, guest->mem, MEM_SIZE);

  gettimeofday(&stop, NULL);
  secs = (double)(stop.tv_usec - start.tv_usec) / 1000000 +
         (double)(stop.tv_sec - start.tv_sec);
  printf("time taken %f\n", secs);
  return 0;
}
