.PHONY: clean, distclean

PREFIX      = riscv64-linux-gnu-
CC	        = $(PREFIX)gcc
OBJDUMP	    = $(PREFIX)objdump

ARCH_FLAGS  = -march=rv32i -mabi=ilp32
CFLAGS      = $(ARCH_FLAGS) -O0 -static -fno-pie -fno-pic -fno-stack-protector
LDFLAGS     = $(ARCH_FLAGS) -L. -static -fno-pie -fno-pic -fno-stack-protector -T./link.ld -nostdlib -nostartfiles
OBJDFLAGS   = -D --section=.text --section=.data

KITELIB 	= syscalls/* crt0.s

PROG ?= simply_exit
BINARIES_PATH = ../binaries

$(PROG): $(PROG).c
	$(CC) -c $(CFLAGS) -I. -o $(PROG).o $(PROG).c
	$(CC) -O0 $(LDFLAGS) -I. -o $(BINARIES_PATH)/$(PROG) $(PROG).o $(KITELIB)

obj:
	$(OBJDUMP) -D $(BINARIES_PATH)/$(PROG) > $(PROG).objdump
	readelf -a $(BINARIES_PATH)/$(PROG) > $(PROG).elf

clean:
	rm $(PROG) $(PROG).o $(PROG).lst $(PROG).objdump $(PROG).elf

distclean:
	rm *.o *.lst *.objdump *.elf
