# eBPF Makefile for KMIM
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')

# BPF object file
BPF_OBJ = kmim.bpf.o

# Include directories
INCLUDES := -I/usr/include -I/usr/include/$(shell uname -m)-linux-gnu

# Compilation flags
CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 | \
	sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-I\1|p }')

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES)

# Build targets
.PHONY: all clean check test install

all: $(BPF_OBJ)

$(BPF_OBJ): kmim.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@
	@echo "✅ Successfully compiled eBPF program: $@"
	@file $@

clean:
	rm -f *.o
	@echo "🧹 Cleaned build artifacts"

# For development - check syntax without compiling
check:
	$(CLANG) $(BPF_CFLAGS) -fsyntax-only kmim.bpf.c
	@echo "✅ Syntax check passed"

# Test the compiled object
test: $(BPF_OBJ)
	@echo "🧪 Testing eBPF object..."
	python3 test_ebpf.py

# Install to parent directory
install: $(BPF_OBJ)
	cp $(BPF_OBJ) ../
	@echo "📦 Installed $(BPF_OBJ) to parent directory"

# Display information about the compiled object
info: $(BPF_OBJ)
	@echo "📊 eBPF Object Information:"
	@echo "File: $(BPF_OBJ)"
	@file $(BPF_OBJ)
	@echo ""
	@echo "📏 Size: $$(stat -c%s $(BPF_OBJ)) bytes"
	@echo ""
	@echo "🔍 Sections:"
	@llvm-objdump -h $(BPF_OBJ) | grep -E "(Idx|tp/|maps|license)"
	@echo ""
	@echo "🎯 Tracepoints:"
	@llvm-objdump -t $(BPF_OBJ) | grep "tp/"
