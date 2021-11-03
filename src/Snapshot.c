#include "Snapshot.h"
#include <sys/time.h>

struct Snapshot *snapshot;

/*
 * restoreSnapshot
 * restores a prior saved snapshot of the vm to reset the kernel environment.
 * */
int restoreSnapshot(struct kernelGuest *guest) {
  struct timeval start, stop;
  double secs = 0;

  gettimeofday(&start, NULL);

  if (ioctl(guest->vcpu_fd, KVM_SET_SREGS, &snapshot->sregs) < 0)
    err(1, "[!] Failed to set special registers - snapshot");

  if (ioctl(guest->vcpu_fd, KVM_SET_REGS, &snapshot->regs) < 0)
    err(1, "[!] Failed to set registers - snapshot");

  // clear breakpoint
  memcpy(guest->mem, snapshot->mem, MEM_SIZE);

  gettimeofday(&stop, NULL);
  secs = (double)(stop.tv_usec - start.tv_usec) / 1000000 +
         (double)(stop.tv_sec - start.tv_sec);
  printf("time taken %f\n", secs);
  return 0;
}

/*
 * createSnapshot
 * Creates a snapshot of the vm and stores it for later use in restoration.
 * */
int createSnapshot(struct kernelGuest *guest) {
  struct timeval start, stop;
  double secs = 0;

  gettimeofday(&start, NULL);
  snapshot = malloc(sizeof(struct Snapshot));
  memset(snapshot, 0x0, sizeof(struct Snapshot));

  if (ioctl(guest->vcpu_fd, KVM_GET_SREGS, &snapshot->sregs) < 0)
    err(1, "[!] Failed to get special registers");

  if (ioctl(guest->vcpu_fd, KVM_GET_REGS, &snapshot->regs) < 0)
    err(1, "[!] Failed to get registers");

  // clear breakpoint
  snapshot->mem = malloc(MEM_SIZE); // Allocate VM memory
  memcpy(snapshot->mem, guest->mem, MEM_SIZE);

  printf("[*] Writing to File");
  FILE *snapshotDump = fopen("/home/scott/LinuxVR/Snapshot-linux.dump", "w+");
  if (!snapshotDump)
    perror("[!] File Dump failed to open");
  fwrite(snapshot->mem, MEM_SIZE, 1, snapshotDump);
  fclose(snapshotDump);

  gettimeofday(&stop, NULL);
  secs = (double)(stop.tv_usec - start.tv_usec) / 1000000 +
         (double)(stop.tv_sec - start.tv_sec);
  printf("time taken %f\n", secs);
  return 0;
}
