#include <stdio.h>
#include <linux/kvm.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    printf("LateRegistration - Linux Kernel Harness\n");

    int kvmFD = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (!kvmFD) {
        fprintf(stderr, "[ERR] /dev/kvm does not exist on the host OS.\n");
        exit(-1);
    }

    close(kvmFD);
    return 0;
}
