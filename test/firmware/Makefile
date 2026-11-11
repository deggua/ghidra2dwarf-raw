# Builds a raw PPC32 big-endian firmware image (fw.bin) plus a reference
# ELF with real debug info (fw.elf) that is only used to derive ground
# truth for the tests -- the exporter never sees it.

CROSS ?= powerpc-linux-gnu-
CC := $(CROSS)gcc
OBJCOPY := $(CROSS)objcopy
NM := $(CROSS)nm

OPT ?= -O1
OUT ?= build

# -msvr4-struct-return: SVR4/EABI struct returns (r3:r4), as in Ghidra's
# ppc_32.cspec; powerpc-linux-gnu defaults to the Linux (memory) convention.
CFLAGS := $(OPT) -g -mcpu=750 -mhard-float -mbig-endian -msdata=none -G0 -msvr4-struct-return \
          -fno-pic -mno-relocatable -ffreestanding -fno-builtin -fno-inline \
          -fno-asynchronous-unwind-tables -fno-stack-protector -Wall -Wextra
ASFLAGS := -mcpu=750 -Wa,-mregnames -fno-pic
LDFLAGS := -nostdlib -static -Wl,--build-id=none -Wl,-T,link.ld -Wl,--no-warn-rwx-segments

all: $(OUT)/fw.bin $(OUT)/symbols.txt

$(OUT):
	mkdir -p $(OUT)

$(OUT)/crt0.o: crt0.S | $(OUT)
	$(CC) $(ASFLAGS) -c $< -o $@

$(OUT)/main.o: main.c fw.h edge.h | $(OUT)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT)/edge.o: edge.c fw.h edge.h | $(OUT)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT)/edge_asm.o: edge_asm.S | $(OUT)
	$(CC) $(ASFLAGS) -c $< -o $@

OBJS := $(OUT)/crt0.o $(OUT)/main.o $(OUT)/edge.o $(OUT)/edge_asm.o

$(OUT)/fw.elf: $(OBJS) link.ld
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS) -o $@ -lgcc

$(OUT)/fw.bin: $(OUT)/fw.elf
	$(OBJCOPY) -O binary $< $@

# name address size type -- used by the Ghidra setup script to recreate
# "human" annotations (function names, global labels) in the raw import.
$(OUT)/symbols.txt: $(OUT)/fw.elf
	$(NM) -S --defined-only $< | awk 'NF==4 && ($$3 ~ /[TtDdBbRr]/) {print $$4, "0x"$$1, "0x"$$2, $$3}' > $@

clean:
	rm -rf $(OUT)

.PHONY: all clean
