# Tuscan Leather

A Linux Kernel Snapshot Fuzzer using KVM.

Tuscan Leather is a Linux Kernel snapshot fuzzer. The goal for this project is to be able to fuzz kernel systems that
would ordinarily require time-consuming environment setup that would be difficult to reproduce solely using unsupervised
coverage based fuzzing. To aid us in this project we will use the
[Kernel Virtual Machine Platform](https://www.linux-kvm.org/page/Main_Page) (KVM) to create our virtual machines. The
design of the fuzzer component of this project will be based on LibFuzzer where the developer has to define the fuzzing
environment through the use of a C program acting as an initrd and an ioctl-based API provided by the OS Handler device
driver.

## Usage

`./Tuscan-Leather <Path to bzImage> <initrd> -j <jobs>`

## OS Handler

The OS Handler is a character device driver that allows the fuzz case runner to issue IOCTL commands that are received
by the KVM hypervisor. Available commands are in [fuzzRunner.h](os-handler/fuzzRunner.h).
