#ifndef LATEREGISTRATION_SNAPSHOT_H
#define LATEREGISTRATION_SNAPSHOT_H

#include "kernelVM.h"

void *memorySnapshot;

int restoreSnapshot(struct kernelGuest *guest);
int createSnapshot(struct kernelGuest *guest);

#endif //LATEREGISTRATION_SNAPSHOT_H
