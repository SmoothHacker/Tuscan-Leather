#include <err.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>

#include "kernelVM.h"

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t cyc_reset_mutex = PTHREAD_MUTEX_INITIALIZER;

struct worker_args {
  char *kernel_img_path;
  char *initrd_img_path;
  kernelGuest *guest;
};

void worker(struct worker_args *args) {
  args->guest->kvm_fd = open("/dev/kvm", O_RDWR | O_CLOEXEC);
  if (args->guest->kvm_fd == -1)
    err(1, "/dev/kvm");

  // Make sure we have the stable version of the API
  int ret = ioctl(args->guest->kvm_fd, KVM_GET_API_VERSION, NULL);
  if (ret == -1)
    err(1, "KVM_GET_API_VERSION");
  if (ret != 12)
    errx(1, "KVM_GET_API_VERSION %d, expected 12", ret);

  createKernelVM(args->guest);
  printf("[*] Created KernelVM\n");

  loadKernelVM(args->guest, args->kernel_img_path, args->initrd_img_path);

  printf("[*] Loaded kernel image: %s\n", args->kernel_img_path);
  printf("[*] Loaded initrd image: %s\n", args->initrd_img_path);
  printf("[*] Starting up VM\n");

  runKernelVM(args->guest);
  cleanupKernelVM(args->guest);
  printf("[*] Destroyed Kernel VM - Success\n");
  pthread_exit(0);
}

int main(int argc, char **argv) {
  if (argc != 3) {
    fprintf(stderr, "Usage: ./Tuscan-Leather <bzImage> <initrd>\n");
    return -1;
  }

  printf("Tuscan-Leather - Linux Kernel Fuzzer\n");

  // Initialize statistics Structure
  statistics *stats = malloc(sizeof(statistics));
  stats->cycles_reset = 0;
  stats->cycles_run = 0;
  stats->cycles_vmexit = 0;
  stats->last_report = 0;

  kernelGuest *guest = malloc(sizeof(kernelGuest));
  guest->stats = stats;

  struct worker_args args = {
      .guest = guest,
      .kernel_img_path = argv[1],
      .initrd_img_path = argv[2],
  };

  pthread_t worker_thread_id;
  pthread_mutex_lock(&mutex);
  int ret =
      pthread_create(&worker_thread_id, NULL, (void *(*)(void *))worker, &args);
  if (ret) {
    err(-1, "[!] Failed to create thread!\n");
  }

  while (1) {
    pthread_cond_wait(&cond, &mutex);
    break;
  }

  // Wait for snapshot to be created
  clock_t start = clock();
  while (1) {
    struct timespec ts = {
        .tv_sec = 0,
        .tv_nsec = 100000000,
    };
    nanosleep(&ts, NULL);

    clock_t elapsed = clock() - start;
    double duration = ((double)elapsed) / CLOCKS_PER_SEC;

    pthread_mutex_lock(&cyc_reset_mutex);
    uint64_t crst = stats->cycles_reset;
    uint64_t crun = stats->cycles_run;
    pthread_mutex_unlock(&cyc_reset_mutex);

    uint64_t ctot = crst + crun;
    double prst = (double)crst / (double)ctot;
    double prun = (double)crun / (double)ctot;
    printf("[%f] reset %f | run %f\n", duration, prst, prun);
  }
}
