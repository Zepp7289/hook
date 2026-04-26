ifndef TARGET_COMPILE
    TARGET_COMPILE = aarch64-none-elf-
endif

ifndef KP_DIR
    KP_DIR = ../KernelPatch
endif


CC = $(TARGET_COMPILE)gcc
LD = $(TARGET_COMPILE)ld

MODULE_NAME := hook

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include

INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

# CFLAGS := -Wall -Wextra -Wunused-macros -Wunused-parameter

objs := $(MODULE_NAME).o

all: $(MODULE_NAME).kpm

$(MODULE_NAME).kpm: ${objs}
	${CC} -r -o $@ $^

%.o: %.c
	${CC} $(CFLAGS) $(INCLUDE_FLAGS) -c -O2 -o $@ $<

ifeq ($(OS),Windows_NT)
    RM = del /f /q
else
    RM = rm -f
endif

.PHONY: clean

clean:
	$(RM) *.o *.kpm