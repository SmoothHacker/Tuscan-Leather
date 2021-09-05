#include "kernelVM.h"

int createKernelVM(struct kernelGuest *guest) {
    if((guest->vmfd = ioctl(guest->kvm_fd, KVM_CREATE_VM, 0)) < 0)
        err(1, "[!] VM creation failed");

    if(ioctl(guest->vmfd, KVM_SET_TSS_ADDR, 0xffffd000) < 0)
        err(1, "[!] Failed to set TSS addr");

    uint64_t map_addr = 0xffffc000;
    if(ioctl(guest->vmfd, KVM_SET_IDENTITY_MAP_ADDR, &map_addr) < 0)
        err(1, "[!] Failed to set identity map addr");

    if(ioctl(guest->vmfd, KVM_CREATE_IRQCHIP, 0) < 0)
        err(1, "[!] Failed to create irq chip");

    struct kvm_pit_config pit = {.flags = 0};
    if(ioctl(guest->vmfd, KVM_CREATE_PIT2, &pit) < 0)
        err(1, "[!] Failed to create i8254 interval timer");

    guest->mem = mmap(NULL, 1 << 30, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if(!guest->mem)
        err(1, "[!] Failed to mmap VM memory");

    struct kvm_userspace_memory_region region = {
            .slot = 0,
            .flags = 0,
            .guest_phys_addr = 0,
            .memory_size = 1 << 30,
            .userspace_addr = (uint64_t) guest->mem
    };

    if(ioctl(guest->vmfd, KVM_SET_USER_MEMORY_REGION, &region) < 0)
        err(1, "[!] Failed to set user memory region");

    guest->vcpu_fd = ioctl(guest->vmfd, KVM_CREATE_VCPU, 0);
    if(guest->vcpu_fd < 0)
        err(1, "[!] Failed to create vcpu");

    initVMRegs(guest);
    createCPUID(guest);
    return 0;
};

int loadKernelVM(struct kernelGuest *guest, const char* kernelImagePath, const char* initrdImagePath) {
    size_t dataSize;
    void *data;
    int fd = open(kernelImagePath, O_RDONLY);
    if (fd < 0) {
        return 1;
    }
    struct stat st;
    fstat(fd, &st);
    data = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    dataSize = st.st_size;
    close(fd);

    struct boot_params *boot = (struct boot_params *)(((uint8_t *)guest->mem) + 0x10000);
    void *cmdline = (void *)(((uint8_t *)guest->mem) + 0x20000);
    void *kernel = (void *)(((uint8_t *)guest->mem) + 0x100000); // Loads protected mode kernel

    memset(boot, 0, sizeof(struct boot_params));
    memmove(boot, data, sizeof(struct boot_params));
    size_t setup_sectors = boot->hdr.setup_sects;
    size_t setupSize = (setup_sectors + 1) * 512;
    boot->hdr.vid_mode = 0xFFFF; // VGA
    boot->hdr.type_of_loader = 0xFF;
    boot->hdr.loadflags |= CAN_USE_HEAP | 0x01 | KEEP_SEGMENTS;
    boot->hdr.heap_end_ptr = 0xFE00;
    boot->hdr.ext_loader_ver = 0x0;
    boot->hdr.cmd_line_ptr = 0x20000;
    memset(cmdline, 0, boot->hdr.cmdline_size);
    memcpy(cmdline, "console=ttyS0", 14);
    memmove(kernel, (char *)data + setupSize, dataSize - setupSize);

    // Setup initrd
    size_t initrdSize;
    int initrdFD = open(initrdImagePath, O_RDONLY);
    if (fd < 0) {
        return 1;
    }
    fstat(initrdFD, &st);
    void *initrdData = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, initrdFD, 0);
    initrdSize = st.st_size;
    close(initrdFD);

    unsigned long addr = boot->hdr.initrd_addr_max & ~0xfffff;
    for (;;) {
        if (addr < 0x100000UL) {
            printf("Not enough memory for initrd");
            return 0;
        }
        else if (addr < ((1 << 30) - st.st_size))
            break;
        addr -= 0x100000;
    }
    printf("initrd address: %lx\n", addr);
    boot->hdr.ramdisk_image = addr;
    boot->hdr.ramdisk_size = st.st_size;
    void *initrd = (void *)(((uint8_t *)guest->mem) + addr);
    memmove(initrd, initrdData, boot->hdr.ramdisk_size);
    return 0;
};

int cleanupKernelVM(struct kernelGuest *guest) {
    close(guest->vcpu_fd);
    close(guest->vmfd);
    close(guest->kvm_fd);
    munmap(guest->mem, 1 << 30);
    return 0;
};

int runKernelVM(struct kernelGuest *guest) {
    int run_size = ioctl(guest->kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
    struct kvm_run *run = mmap(0, run_size, PROT_READ | PROT_WRITE, MAP_SHARED, guest->vcpu_fd, 0);
    for (;;) {
        int ret = ioctl(guest->vcpu_fd, KVM_RUN, 0);
        if (ret < 0) {
            err(1, "kvm_run failed");
        }

        switch (run->exit_reason) {
            case KVM_EXIT_IO:
                if (run->io.port == 0x3f8 && run->io.direction == KVM_EXIT_IO_OUT) {
                    uint32_t size = run->io.size;
                    uint64_t offset = run->io.data_offset;
                    printf("%.*s", size * run->io.count, (char *)run + offset);
                } else if (run->io.port == 0x3f8 + 5 &&
                run->io.direction == KVM_EXIT_IO_IN) {
                    char *value = (char *)run + run->io.data_offset;
                    *value = 0x20;
                }
                break;
            case KVM_EXIT_SHUTDOWN:
                printf("shutdown\n");
                return 0;
            default:
                printf("reason: %d\n", run->exit_reason);
                return -1;
        }
    }
};

int initVMRegs(struct kernelGuest *guest) {
    struct kvm_regs regs;
    struct kvm_sregs sregs;
    if(ioctl(guest->vcpu_fd, KVM_GET_SREGS, &sregs) < 0)
        err(1, "[!] Failed to get special registers");

    sregs.cs.base = 0;
    sregs.cs.limit = ~0;
    sregs.cs.g = 1;

    sregs.ds.base = 0;
    sregs.ds.limit = ~0;
    sregs.ds.g = 1;

    sregs.fs.base = 0;
    sregs.fs.limit = ~0;
    sregs.fs.g = 1;

    sregs.gs.base = 0;
    sregs.gs.limit = ~0;
    sregs.gs.g = 1;

    sregs.es.base = 0;
    sregs.es.limit = ~0;
    sregs.es.g = 1;

    sregs.ss.base = 0;
    sregs.ss.limit = ~0;
    sregs.ss.g = 1;

    sregs.cs.db = 1;
    sregs.ss.db = 1;
    sregs.cr0 |= 1; // enable protected mode - required for linux to boot

    if (ioctl(guest->vcpu_fd, KVM_SET_SREGS, &sregs) < 0)
        err(1, "[!] Failed to set special registers");

    if (ioctl(guest->vcpu_fd, KVM_GET_REGS, &regs) < 0)
        err(1, "[!] Failed to get registers");

    regs.rflags = 2;
    regs.rip = 0x100000;
    regs.rsi = 0x10000;

    if (ioctl(guest->vcpu_fd, KVM_SET_REGS, &regs) < 0)
        err(1, "[!] Failed to set registers");
    return 0;
};

int createCPUID(struct kernelGuest *guest) {
    struct {
        uint32_t nent;
        uint32_t padding;
        struct kvm_cpuid_entry2 entries[100];
    } kvm_cpuid;
    kvm_cpuid.nent = sizeof(kvm_cpuid.entries) / sizeof(kvm_cpuid.entries[0]);
    ioctl(guest->kvm_fd, KVM_GET_SUPPORTED_CPUID, &kvm_cpuid);

    for (unsigned int i = 0; i < kvm_cpuid.nent; i++) {
        struct kvm_cpuid_entry2 *entry = &kvm_cpuid.entries[i];
        if (entry->function == KVM_CPUID_SIGNATURE) {
            entry->eax = KVM_CPUID_FEATURES;
            entry->ebx = 0x4b4d564b; // KVMK
            entry->ecx = 0x564b4d56; // VMKV
            entry->edx = 0x4d;       // M
        }
    }
    ioctl(guest->vcpu_fd, KVM_SET_CPUID2, &kvm_cpuid);
    return 0;
};
