#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/printk.h>

int module_entry(void) {
  printk(KERN_INFO "[*] OS Handler installed VM side\n[*] Attempting to "
                   "communicate with the hypervisor\n");

  return 0;
}

void module_cleanup(void) { printk(KERN_INFO "[*] OS Handler Exiting\n"); }

module_init(module_entry);
module_exit(module_cleanup);

MODULE_AUTHOR("SmoothHacker");
MODULE_LICENSE("Personal");
MODULE_DESCRIPTION("OS Handler for LateRegistration.");
