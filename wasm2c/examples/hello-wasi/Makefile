#assumes wasi-sdk installed system wide in default location
REPO_PATH=$(shell realpath ../../../..)
WASI_SDK_ROOT=$(REPO_PATH)/wasi-sdk
WABT_SRC_ROOT=$(REPO_PATH)/hfi_wasm2c_sandbox_compiler/

WABT_BIN_CHOICE=build_debug_hfiemulate
WASM_SECURITY_FLAGS=-DWASM_USE_HFI -DHFI_EMULATION

WABT_BIN_ROOT=$(REPO_PATH)/hfi_wasm2c_sandbox_compiler/$(WABT_BIN_CHOICE)

WASI_CLANG=$(WASI_SDK_ROOT)/bin/clang
WASI_SYSROOT=$(WASI_SDK_ROOT)/share/wasi-sysroot
WASM2C_RUNNER=$(WABT_BIN_ROOT)/wasm2c-runner

#CFLAGS for compiling files to place nice with wasm2c
WASM_CFLAGS=-Wl,--export-all -Wl,--global-base=150000 -Wl,-z,stack-size=1048576 -Wl,--growable-table


WASM2C=$(WABT_BIN_ROOT)/wasm2c

WASM2C_RUNTIME_PATH=$(WABT_SRC_ROOT)/wasm2c/
WASM2C_RUNTIME_FILES=$(addprefix $(WASM2C_RUNTIME_PATH), wasm-rt-impl.c wasm-rt-os-unix.c uvwasi-rt.c)

HFIPATH=$(REPO_PATH)/hw_isol_gem5/tests/test-progs/hfi/

UVWASI_PATH=$(WABT_SRC_ROOT)/third_party/uvwasi

DEPS=-I$(UVWASI_PATH)/include -L$(WABT_BIN_ROOT)/_deps/libuv-build -L$(WABT_BIN_ROOT)/third_party/uvwasi

LIBS=-luvwasi_a -luv -lpthread

ALL_RESULTS=hello.wasm hello.wasm.c hello.so

all: wasmrt $(ALL_RESULTS)

$(WABT_BIN_ROOT):
	cd $(REPO_PATH)/mybuild && make ../build_debug_hfiemulate_rr

wasmrt: $(WABT_BIN_ROOT)
	cd $(WABT_BIN_ROOT) && make -j$(shell nproc)

clean:
	rm -rf $(ALL_RESULTS) hello.wasm.h *.o

hello.wasm: hello.c
	$(WASI_CLANG) --sysroot $(WASI_SYSROOT) $(WASM_CFLAGS) hello.c -o hello.wasm

hello.wasm.c: hello.wasm
	$(WASM2C) hello.wasm -o hello.wasm.c

hello.so: hello.wasm.c $(WASM2C_RUNTIME_FILES)
	$(CC) -g -shared -fPIC $(WASM_SECURITY_FLAGS) hello.wasm.c -o hello.so -I$(WASM2C_RUNTIME_PATH) -I$(HFIPATH) $(WASM2C_RUNTIME_FILES) $(DEPS) $(LIBS)

run: hello.so
	$(WASM2C_RUNNER) $(PWD)/hello.so

run-gdb: hello.so
	gdb --args $(WASM2C_RUNNER) $(PWD)/hello.so

run-rr: hello.so
	rr record $(WASM2C_RUNNER) $(PWD)/hello.so
