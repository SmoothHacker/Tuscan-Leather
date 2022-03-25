#include "breakpoint.h"

uint64_t *breakpointAddrs;

int addBreakpoint(kernelGuest *guest, uint64_t addr) {
  *(uint8_t *)(guest->mem + addr) = 0xcc;
  return 0;
};

int delBreakpoint(kernelGuest *guest, uint64_t addr) { return 0; };

int loadAddresses(const char *filePath) {
  FILE *systemMapFD = fopen(filePath, "r");
  char line[256];
  uint64_t countOfTextSymbols = 0;

  // count number of text symbols
  while (fgets(line, sizeof(line), systemMapFD)) {
    unsigned long long addr;
    uint8_t symbolType;
    char symbolName[128];
    scanf(line, "%llx %c %s", &addr, &symbolType, symbolName);
    if (symbolType == 'T' || symbolType == 't') {
      countOfTextSymbols++;
    }
  }
  printf("[*] Number of Text Symbols: %ld\n", countOfTextSymbols);

  fclose(systemMapFD);
  return 0;
};
