#include <err.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>

#include "kernelVM.h"

int main(int argc, char **argv) {
    int kvm, ret;

    printf("LateRegistration - Linux Kernel Hypervisor\n");
    struct kernelGuest guest;

    guest.kvm_fd = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (guest.kvm_fd == -1)
        err(1, "/dev/kvm");

    // Make sure we have the stable version of the API
    ret = ioctl(guest.kvm_fd, KVM_GET_API_VERSION, NULL);
    if (ret == -1)
        err(1, "KVM_GET_API_VERSION");
    if (ret != 12)
        errx(1, "KVM_GET_API_VERSION %d, expected 12", ret);

    createKernelVM(&guest);
    printf("[*] Created KernelVM\n");
    loadKernelVM(&guest, argv[1]);
    printf("[*] Loaded kernel image %s\n", argv[1]);
    printf("[*] Starting up VM\n");
    runKernelVM(&guest);
    cleanupKernelVM(&guest);
    printf("[*] Destroyed Kernel VM\n");
}