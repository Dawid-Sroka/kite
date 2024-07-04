.PHONY: clean, distclean

PREFIX      = riscv32-unknown-elf-
CC	        = $(PREFIX)gcc
OBJDUMP	    = $(PREFIX)objdump

CFLAGS      = -O0 -march=rv32i -mabi=ilp32 -static
LDFLAGS     = -L. -T./link.ld -nostdlib -nostartfiles
OBJDFLAGS   = -D --section=.text --section=.data

KITELIB 	= crt0.s exit.s execve.s fork.s write.s read.s open.s pipe.s debug_print.s

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
