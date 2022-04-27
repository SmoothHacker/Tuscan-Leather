#include <linux/kvm.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>

#include "kernelVM.h"

struct worker_args {
  char *kernel_img_path;
  char *initrd_img_path;
  kernelGuest *guest;
};

uint64_t numberOfJobs = 0;
pid_t *childPids;

void kill_child() {
  if (childPids == nullptr)
    return;
  for (int i = 0; i < numberOfJobs; ++i) {
    kill(childPids[i], SIGKILL);
  }
}

void worker(struct worker_args *args) {
  args->guest->kvm_fd = open("/dev/kvm", O_RDWR | O_CLOEXEC);
  if (args->guest->kvm_fd == -1)
    ERR("/dev/kvm");

  // Make sure we have the stable version of the API
  int ret = ioctl(args->guest->kvm_fd, KVM_GET_API_VERSION, NULL);
  if (ret == -1)
    ERR("KVM_GET_API_VERSION");
  if (ret != 12)
    errx(-1, "[!] KVM_GET_API_VERSION %d, expected 12", ret);

  createKernelVM(args->guest);
  loadKernelVM(args->guest, args->kernel_img_path, args->initrd_img_path);

  printf("[*] Starting up VM\n");
  runKernelVM(args->guest);
  cleanupKernelVM(args->guest);
  printf("[*] Destroyed Kernel VM - Success\n");
}

int main(int argc, char **argv) {
  if (argc != 5) {
    fprintf(stderr, "Usage: ./Tuscan-Leather <bzImage> <initrd> -j <jobs>\n");
    return -1;
  }

  printf("Tuscan-Leather - Linux Kernel Fuzzer\n");

  // Initialize statistics Structure
  auto *stats =
      (statistics *)mmap(NULL, sizeof(statistics), PROT_READ | PROT_WRITE,
                         MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  stats->cycles_reset = 0;
  stats->cycles_run = 0;
  stats->cycles_vmexit = 0;
  stats->cases = 0;
  stats->numOfPagesReset = 0;

  stats->lock = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
  pthread_mutex_init(stats->lock, NULL);

  auto *guest =
      (kernelGuest *)mmap(NULL, sizeof(kernelGuest), PROT_READ | PROT_WRITE,
                          MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  guest->stats = stats;

  struct worker_args args = {
      .kernel_img_path = argv[1],
      .initrd_img_path = argv[2],
      .guest = guest,
  };

  signal(SIGINT, (void (*)(int))kill_child);
  numberOfJobs = strtoul(argv[4], NULL, 10);
  childPids = (pid_t *)malloc(numberOfJobs * sizeof(pid_t));

  for (int i = 0; i < numberOfJobs; i++) {
    pid_t pid = fork();
    if (pid == 0) {
      worker(&args);
      exit(0);
    } else if (pid == -1) {
      ERR("Fork Failed");
    }
    childPids[i] = pid;
  }

  // open stats.txt
  FILE *statslogFD = fopen("stats.txt", "w");

  // Wait for snapshot to be created
  printf("[*] Waiting for VM to update stats\n");
  sleep(5);

  struct timespec start, end;
  clock_gettime(CLOCK_THREAD_CPUTIME_ID, &start);
  while (1) {
    struct timespec ts = {
        .tv_sec = 0,
        .tv_nsec = 100000000,
    };
    nanosleep(&ts, NULL);

    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &end);
    double duration = (double)(end.tv_nsec - start.tv_nsec) / 1e6;

    pthread_mutex_lock(stats->lock);
    uint64_t crst = stats->cycles_reset;
    uint64_t crun = stats->cycles_run;
    uint64_t cases = stats->cases;
    uint64_t numReset = stats->numOfPagesReset;
    uint64_t pcs = stats->totalPCs;
    pthread_mutex_unlock(stats->lock);

    uint64_t ctot = crst + crun;
    double prst = (double)crst / (double)ctot;
    double prun = (double)crun / (double)ctot;
    double cps = (double)cases / duration;

    if (duration > 60.0f) {
      kill_child();
      return 0;
    }
    printf("[%f] cps %f | reset %f | run %f | cases %lu | cov %lu\n", duration,
           cps, prst, prun, cases, pcs);
    fprintf(statslogFD, "%f %f %f %lu %f %lu\n", duration, prst, prun, cases,
            cps, numReset);
  }
}
