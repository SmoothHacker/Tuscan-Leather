# Tuscan Leather

A Linux Kernel Snapshot Fuzzer using KVM.

Late Registration is the name for a Linux Kernel snapshot fuzzer. The goal for this project is to be able to fuzz
complex functionality of the Linux Kernel that would ordinarily require time consuming environment setup that would be
difficult to reproduce solely using coverage based fuzzing techniques. To aid us in this project we will use the
[Kernel Virtual Machine Platform](https://www.linux-kvm.org/page/Main_Page)(KVM) to create our virtual machines. The
design of the fuzzer component of this project will be based on LibFuzzer where the developer has to define the fuzzing
environment through the use of a C program acting as an initrd and an ioctl-based API provided by the OS Handler
character device driver.

## Usage

`./Tuscan-Leather <Path to bzImage> <initrd>`

## OS Handler

The OS Handler is a character device driver that allows the fuzz case runner to issue IOCTL commands that are received
by the KVM hypervisor. Available commands are in [fuzzRunner.h](os-handler/fuzzRunner.h).

## Future Plans

1. Device Fuzzing

* Ability to emulate physical devices to fuzz device drivers
    * emulation allows ability to have introspection at the "hardware" end
* Possibility to fuzz PCI, USB, etc...

2. OS Handler

* Kernel module that allows communication between the harness and the userland in the guest vm.
* character device driver with an ioctl-based API that issues commands via I/O ports and MMIO.

3. Snapshots

* Would like to implement a delta-based snapshot restoration scheme. Should lead to faster restoration times and more
  fuzz cases per second.

4. Breakpoint API

* Allows easy way to introspect kernel functions.
    * Kernel Module Loading, Kernel Panics, Coverage Info, I/O port allocation, task structures.
    * Requires way to interact with virtual memory.
* Desired breakpoints to be fed by a text file containing kernel addresses

5. Status Menu / Code Base Refactor

* Show statistics about the vm
    * Clk cycles/Reset, Mem usage, % in vm code, etc...

6. Mutator for Device Driver Fuzzing

* Structure aware mutator for device driver ioctl fuzzing

7. Multi-vm

* Ability to spin up multiple virtual machines to have concurrent kernel fuzzing
* Requires architecture restructure to manage multiple VMs
* Would use an IPC mechanism to orchestrate threads
