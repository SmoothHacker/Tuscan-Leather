#include "breakpoint.h"

int addBreakpoint(kernelGuest *guest, uint64_t virtAddr) {
  struct kvm_translation kvmTranslation = {.linear_address = virtAddr};
  if (ioctl(guest->vcpu_fd, KVM_TRANSLATE, &kvmTranslation) < 0)
    ERR("KVM_TRANSLATE Failed");

  *(uint8_t *)((uint8_t *)guest->mem + kvmTranslation.physical_address) = 0xcc;
  return 0;
}

int delBreakpoint(kernelGuest *guest, uint64_t addr) { return 0; }

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
}
