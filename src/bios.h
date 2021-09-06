#ifndef LATEREGISTRATION_BIOS_H
#define LATEREGISTRATION_BIOS_H

#include "kernelVM.h"

int setupE820(struct kernelGuest *guest, struct boot_params *boot);

#endif //LATEREGISTRATION_BIOS_H
