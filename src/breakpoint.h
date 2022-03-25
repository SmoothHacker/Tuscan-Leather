#ifndef TUSCAN_LEATHER_BREAKPOINT_H
#define TUSCAN_LEATHER_BREAKPOINT_H

#include "kernelVM.h"

typedef struct {
  uint64_t addr;
  uint8_t code;
} Breakpoint;

extern uint64_t *breakpointAddrs;

int addBreakpoint(kernelGuest *guest, uint64_t addr);

int delBreakpoint(kernelGuest *guest, uint64_t addr);

int loadAddresses(const char *filePath);

#endif // TUSCAN_LEATHER_BREAKPOINT_H
