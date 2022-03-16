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

`./Tuscan-Leather <Path to bzImage> <initrd>`

## OS Handler

The OS Handler is a character device driver that allows the fuzz case runner to issue IOCTL commands that are received
by the KVM hypervisor. Available commands are in [fuzzRunner.h](os-handler/fuzzRunner.h).

## Future Plans

1. Device Fuzzing
   1. Ability to emulate physical devices to fuzz device drivers
      1. emulation allows ability to have introspection at the "hardware" end
   2. Possibility to fuzz PCI, USB, etc...
2. Breakpoint API
   1. Allows easy way to introspect kernel functions.
      1. Kernel Module Loading, Kernel Panics, Coverage Info, I/O port allocation, task structures.
      2. Requires way to interact with virtual memory.
   2. Desired breakpoints to be fed by a text file containing kernel addresses
3. Mutator for Device Driver Fuzzing
   1. Structure aware mutator for device driver ioctl fuzzing
4. Multi-vm
   1. Ability to spin up multiple virtual machines to have concurrent kernel fuzzing
