#ifndef TUSCAN_LEATHER_MUTATION_H
#define TUSCAN_LEATHER_MUTATION_H

#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <unordered_set>

extern std::unordered_set<uint64_t> coveragePCs;
extern uint64_t seed;

int initializeMutationEngine(uint64_t newSeed);
int addPC(uint64_t newPC);
uint64_t getNewByteSequence();
uint64_t getSizeOfSet();

#endif // TUSCAN_LEATHER_MUTATION_H