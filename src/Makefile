OS = $(shell uname)
EXT_LIBS = -lpcap
BASE_FLAGS = -fPIC -Wall -Wextra -pedantic -ggdb -O3 # -DRUN_MAIN
O_FLAGS := $(BASE_FLAGS)

ifeq ($(OS),Darwin)
	COMPILE_MSG = "====Compiling for MacOS===="
	CC = clang
	CC_FLAGS = -framework SystemConfiguration -framework CoreFoundation -shared $(BASE_FLAGS)
else
	COMPILE_MSG = "====Compiling for Linux===="
	CC = gcc
	CC_FLAGS = -shared $(BASE_FLAGS)
endif

SRCS = $(wildcard *.c)
OBJS = $(patsubst %.c, build/%.o, $(SRCS)) # ---> patsubst(pattern, replacement, text) = pattern substitute

TARGET = ../lib/libhexp.so

all: $(TARGET)

$(TARGET): $(OBJS) | ../lib
	@echo $(COMPILE_MSG)
	$(CC) $(CC_FLAGS) $(OBJS) $(EXT_LIBS) -o $@

build/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) -c $(O_FLAGS) $< -o $@

../lib:
	mkdir -p ../lib

.PHONY: clean
clean:
	rm -rf *.o main ../lib/$(notdir $(TARGET)) ./build