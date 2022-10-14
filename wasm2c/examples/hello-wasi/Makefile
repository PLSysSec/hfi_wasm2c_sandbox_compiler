#assumes wasi-sdk installed system wide in default location
ROOT_PATH=$(shell realpath ../../../..)
WASI_SDK_ROOT=$(ROOT_PATH)/wasi-sdk
WABT_SRC_ROOT=$(ROOT_PATH)/hfi_wasm2c_sandbox_compiler/

WABT_BIN_CHOICE=build_debug_hfiemulate2
WASM_SECURITY_FLAGS=-DWASM_USE_HFI -DHFI_EMULATION2

WABT_BIN_ROOT=$(WABT_SRC_ROOT)/$(WABT_BIN_CHOICE)

WASI_CLANG=$(WASI_SDK_ROOT)/bin/clang
WASI_SYSROOT=$(WASI_SDK_ROOT)/share/wasi-sysroot
WASM2C_RUNNER=$(WABT_BIN_ROOT)/wasm2c-runner

#CFLAGS for compiling files to play nice with wasm2c and hfi emulation
WASM_CFLAGS=-Wl,--export-all -Wl,--global-base=150000 -Wl,-z,stack-size=1048576 -Wl,--growable-table

WASM2C=$(WABT_BIN_ROOT)/wasm2c

WASM2C_RUNTIME_PATH=$(WABT_SRC_ROOT)/wasm2c/
WASM2C_RUNTIME_FILES=$(addprefix $(WASM2C_RUNTIME_PATH), wasm-rt-impl.c wasm-rt-os-unix.c uvwasi-rt.c wasm-rt-runner-static.c)
WASM2C_SHADOW_RUNTIME_FILES=$(addprefix $(WASM2C_RUNTIME_PATH), wasm-rt-shadow.cpp)

HFIPATH=$(ROOT_PATH)/hw_isol_gem5/tests/test-progs/hfi/

UVWASI_PATH=$(WABT_SRC_ROOT)/third_party/uvwasi

INCS=-I$(UVWASI_PATH)/include -I$(WASM2C_RUNTIME_PATH) -I$(HFIPATH)
DEPS=-L$(WABT_BIN_ROOT)/_deps/libuv-build -L$(WABT_BIN_ROOT)/third_party/uvwasi

LIBS=-luvwasi_a -luv -lpthread

ALL_RESULTS=hello.wasm hello.wasm.c hello

all: wasmrt $(ALL_RESULTS)

$(WABT_BIN_ROOT):
	cd $(WABT_SRC_ROOT)/mybuild && make ../$(WABT_BIN_CHOICE)

wasmrt: $(WABT_BIN_ROOT)
	cd $(WABT_BIN_ROOT) && make -j$(shell nproc)

clean:
	rm -rf $(ALL_RESULTS) hello.wasm.h *.o

hello.wasm: hello.c
	$(WASI_CLANG) --sysroot $(WASI_SYSROOT) $(WASM_CFLAGS) hello.c -o hello.wasm

hello.wasm.c: hello.wasm
	$(WASM2C) hello.wasm -o hello.wasm.c

hello: hello.wasm.c $(WASM2C_RUNTIME_FILES)
	$(CXX) -g -c $(WASM_SECURITY_FLAGS) $(WASM2C_SHADOW_RUNTIME_FILES) $(INCS)
	$(CC)  -g -c $(WASM_SECURITY_FLAGS) hello.wasm.c $(WASM2C_RUNTIME_FILES) $(INCS)
	$(CXX) -g $(WASM_SECURITY_FLAGS) *.o -o hello $(DEPS) $(LIBS)

run: hello
	$(PWD)/hello

run-gdb: hello
	gdb --args $(PWD)/hello

run-rr: hello
	rr record $(PWD)/hello
