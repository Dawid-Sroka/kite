PREFIX      = riscv32-unknown-elf-
CC	        = $(PREFIX)gcc
OBJDUMP	    = $(PREFIX)objdump

CFLAGS      = -O0 -march=rv32i -mabi=ilp32 -static
LDFLAGS     = -L. -T./link.ld -nostdlib -nostartfiles
OBJDFLAGS   = -D --section=.text --section=.data

KITELIB 		= exit.s crt0.s

PROG = simply_exit
BINARIES_PATH = ../binaries

lib:
	$(CC) -c $(CFLAGS) -I. -o crt0.o crt0.s
	$(CC) -c $(CFLAGS) -I. -o exit.o exit.s

binary:
	$(CC) -c $(CFLAGS) -I. -o $(PROG).o $(PROG).c
	$(CC) -O0 $(LDFLAGS) -I. -o $(BINARIES_PATH)/$(PROG) $(PROG).o $(KITELIB)

obj:
	$(OBJDUMP) -D $(PROG) > $(PROG).objdump
	readelf -a $(PROG) > $(PROG).elf

clean:
	rm $(PROG) $(PROG).o $(PROG).lst $(PROG).objdump $(PROG).elf

distclean:
	rm $(PROG) *.o *.lst *.objdump *.elf
