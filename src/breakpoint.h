#ifndef TUSCAN_LEATHER_BREAKPOINT_H
#define TUSCAN_LEATHER_BREAKPOINT_H

#include "kernelVM.h"

/*
 * Breakpoint API
 * Through this API, we are able to set software breakpoints on the vm. This
 * will allow us to set breakpoints on important functions like `kasan_report`
 * and have the vm kick out to userspace to handle it. From there we can reset
 * the vm or save the testcase used to trip kasan.
 * */
int addBreakpoint(kernelGuest *guest, uint64_t addr);

int delBreakpoint(kernelGuest *guest, uint64_t addr);

int loadAddresses(const char *filePath);

#endif // TUSCAN_LEATHER_BREAKPOINT_H
