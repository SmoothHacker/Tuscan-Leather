#include "mutation.h"

std::unordered_set<uint64_t> coveragePCs;
uint64_t seed;

uint64_t getSizeOfSet() { return coveragePCs.size(); }

int addPC(uint64_t newPC) {
  auto result = coveragePCs.emplace(newPC);
  return result.second;
}

int initializeMutationEngine(uint64_t newSeed) {
  seed = newSeed;
  srand(time(nullptr));
  return 0;
}