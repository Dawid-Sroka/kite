.PHONY: clean, distclean

PREFIX      = riscv64-linux-gnu-
CC	        = $(PREFIX)gcc
OBJDUMP	    = $(PREFIX)objdump

ARCH ?= rv64

ifeq ($(ARCH),rv64)
	ARCH_FLAGS  = -march=rv64i -mabi=lp64
	CFLAGS      = $(ARCH_FLAGS) -O0 -static -fno-pie -fno-pic -fno-stack-protector -mcmodel=medany
else ifeq ($(ARCH),rv32)
	ARCH_FLAGS  = -march=rv32i -mabi=ilp32
	CFLAGS      = $(ARCH_FLAGS) -O0 -static -fno-pie -fno-pic -fno-stack-protector
else
    $(error Unsupported ARCH='$(ARCH)'. Use ARCH=rv64 or ARCH=rv32)
endif

LDFLAGS     = $(ARCH_FLAGS) -L. -static -fno-pie -fno-pic -fno-stack-protector -T./link.ld -nostdlib -nostartfiles
OBJDFLAGS   = -D --section=.text --section=.data

KITELIB 	= syscalls/* crt0.s

PROG ?= simply_exit
BINARIES_PATH = ../binaries

PROGRAMS := page_fault piping simply_execve simply_exit simply_fork simply_write waiting
all : $(BINARIES_PATH) $(PROGRAMS)

$(BINARIES_PATH):
	mkdir -p $(BINARIES_PATH)

%: %.c
	$(CC) -c $(CFLAGS) -I. -o $*.o $*.c
	$(CC) -O0 $(LDFLAGS) -I. -o $(BINARIES_PATH)/$@ $*.o $(KITELIB)

.PHONY: obj
obj: $(addsuffix .objdump, $(PROGRAMS)) $(addsuffix .elf, $(PROGRAMS))

%.objdump: 
	$(OBJDUMP) -D $(BINARIES_PATH)/$* > $@

%.elf:
	readelf -a $(BINARIES_PATH)/$* > $@

.PHONY: clean
clean:
	rm -f $(addprefix $(BINARIES_PATH)/, $(PROGRAMS)) \
	      $(addsuffix .o, $(PROGRAMS)) \
	      $(addsuffix .lst, $(PROGRAMS)) \
	      $(addsuffix .objdump, $(PROGRAMS)) \
	      $(addsuffix .elf, $(PROGRAMS))
