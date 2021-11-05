obj-m := os_handler.o
os_handler-objs := main.o

LinuxSourcePath := # Path to the root of the linux kernel repo

all:
	make -C $(LinuxSourcePath) M=$(PWD) modules

clean:
	make -C $(LinuxSourcePath) M=$(PWD) clean