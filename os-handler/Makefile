obj-m := os_handler.o
os_handler-objs := main.o

LinuxSourcePath := /home/scott/LinuxVR/linux-5.13.9

all:
	make -C $(LinuxSourcePath) M=$(PWD) modules

clean:
	make -C $(LinuxSourcePath) M=$(PWD) clean