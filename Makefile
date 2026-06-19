CC ?= cc
AS ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -O2 -g -D_GNU_SOURCE
LDFLAGS ?=

BIN := pawtrace
BUILD := build
SRC := src/main.c src/trace.c src/decode.c src/remote.c src/proc.c
ASM := asm/arch_x86_64.S
OBJ := $(SRC:%.c=$(BUILD)/%.o) $(ASM:%.S=$(BUILD)/%.o)

.PHONY: all clean examples

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $^

$(BUILD)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -Iinclude -c -o $@ $<

$(BUILD)/%.o: %.S
	@mkdir -p $(dir $@)
	$(AS) -c -o $@ $<

examples: examples/chatter

examples/chatter: examples/chatter.c asm/arch_x86_64.S
	$(CC) $(CFLAGS) -Iinclude -o $@ examples/chatter.c asm/arch_x86_64.S

clean:
	rm -rf $(BUILD) $(BIN) examples/chatter
