#include <asm/io.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/ioctl.h>
#include <linux/kdev_t.h>
#include <asm/io.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/ioctl.h>
#include <linux/kdev_t.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>    //kmalloc()
#include <linux/uaccess.h> //copy_to/from_user()

#include "fuzzRunner.h"

#define DEV_MAJOR 24
#define DEVICE_NAME "tl-hypervisor"
#define PORT_1 0xdead

// Function Prototypes
static int tl_driver_init(void);
static void tl_driver_exit(void);
static int open(struct inode *inode, struct file *file);
static int release(struct inode *inode, struct file *file);
static ssize_t read(struct file *filp, char __user *buf, size_t len,
                    loff_t *off);
static ssize_t write(struct file *filp, const char *buf, size_t len,
                     loff_t *off);
static long tl_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

// File operation sturcture
static struct file_operations fops = {
    .owner = THIS_MODULE,
    .read = read,
    .write = write,
    .open = open,
    .unlocked_ioctl = tl_ioctl,
    .release = release,
};

static dev_t device_major;

// This function will be called when we open the Device file
static int open(struct inode *inode, struct file *file) {
  pr_alert("[!] tl-hypervisor opened\n");
  return 0;
}

// This function will be called when we close the Device file
static int release(struct inode *inode, struct file *file) { return 0; }

// This function will be called when we read the Device file
static ssize_t read(struct file *filp, char __user *buf, size_t len,
                    loff_t *off) {
  pr_info("Read Function\n");
  return 0;
}

// This function will be called when we write the Device file
static ssize_t write(struct file *filp, const char __user *buf, size_t len,
                     loff_t *off) {
  return len;
}

// This function will be called when we write IOCTL on the Device file
static long tl_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
  // pr_alert("[!] tl-hypervisor ioctl issued - cmd: %d\n", cmd);

  switch (cmd) {
  case TAKE_SNAPSHOT:
    // pr_alert("[*] Snapshoting VM\n");
    outb_p(TAKE_SNAPSHOT, PORT_1);
    break;
  case RESTORE_VM:
    // pr_alert("[*] Restoring VM\n");
    outb_p(RESTORE_VM, PORT_1);
    break;
  default:
    break;
  }

  return 0;
}

// Module Init function
static int __init tl_driver_init(void) {
  device_major = register_chrdev(32, DEVICE_NAME, &fops);

  if (device_major < 0) {
    printk(KERN_ALERT "Device Registration failed with %d\n", device_major);
    return device_major;
  }

  if (!request_region(PORT_1, 1, DEVICE_NAME)) {
    pr_alert("[!] IO port allocation of %x failed\n", PORT_1);
    return -ENODEV;
  }

  return 0;
}

// Module exit function
static void tl_driver_exit(void) {
  // Not needed since VM will be destroyed
}

module_init(tl_driver_init);
module_exit(tl_driver_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Scott Lagler <laglerscott@gmail.com>");
MODULE_DESCRIPTION("Tuscan Leather - OS Handler");
MODULE_VERSION("1.0");