#include <linux/kvm.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <signal.h>

#include "kernelVM.h"

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

pthread_barrier_t init_barrier;

struct worker_args {
  char *kernel_img_path;
  char *initrd_img_path;
  kernelGuest *guest;
};

uint64_t numberOfJobs = 0;
pid_t *childPids;

void kill_child(int sig) {
  if (childPids == NULL)
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
  // printf("[*] Created KernelVM\n");

  loadKernelVM(args->guest, args->kernel_img_path, args->initrd_img_path);

  // printf("[*] Loaded kernel image: %s\n", args->kernel_img_path);
  // printf("[*] Loaded initrd image: %s\n", args->initrd_img_path);
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
  statistics *stats = mmap(NULL, sizeof(statistics), PROT_READ | PROT_WRITE,
                           MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  stats->cycles_reset = 0;
  stats->cycles_run = 0;
  stats->cycles_vmexit = 0;
  stats->cases = 0;
  stats->numOfPagesReset = 0;

  stats->lock = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
  pthread_mutex_init(stats->lock, NULL);

  kernelGuest *guest = malloc(sizeof(kernelGuest));
  guest->stats = stats;

  struct worker_args args = {
      .guest = guest,
      .kernel_img_path = argv[1],
      .initrd_img_path = argv[2],
  };

  numberOfJobs = strtoul(argv[4], NULL, 10);
  childPids = malloc(numberOfJobs * sizeof(pid_t));
  pthread_mutex_lock(&mutex);

  signal(SIGINT, (void (*)(int))kill_child);
  for (int i = 0; i < numberOfJobs; i++) {
    childPids[i] = fork();
    if (childPids[i] == 0) {
      worker(&args);
      exit(0);
    } else if (childPids[i] == -1) {
      ERR("Fork Failed");
    }
  }

  // open stats.txt
  FILE *statslogFD = fopen("stats.txt", "w");

  while (1) {
    if (stats->cases != 0)
      break;
  }

  // Wait for snapshot to be created
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
    pthread_mutex_unlock(stats->lock);

    uint64_t ctot = crst + crun;
    double prst = (double)crst / (double)ctot;
    double prun = (double)crun / (double)ctot;
    double cps = (double)cases / duration;
    printf("[%f] cps %f | reset %f | run %f | cases %lu\n", duration, cps, prst,
           prun, cases);
    fprintf(statslogFD, "%f %f %f %lu %f %lu\n", duration, prst, prun, cases,
            cps, numReset);
  }
}
