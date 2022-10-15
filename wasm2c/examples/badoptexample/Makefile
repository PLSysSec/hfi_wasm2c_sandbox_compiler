#assumes wasi-sdk installed system wide in default location
ROOT_PATH=$(shell realpath ../../../..)
WASI_SDK_ROOT=$(ROOT_PATH)/wasi-sdk
WABT_SRC_ROOT=$(ROOT_PATH)/hfi_wasm2c_sandbox_compiler/

WABT_BIN_CHOICE=build_debug_hfiemulate2_shadowlog
WASM_SECURITY_FLAGS=-DWASM_USE_HFI -DHFI_EMULATION2 -DWASM_CHECK_SHADOW_MEMORY -DWASM_CHECK_SHADOW_MEMORY_LOG

WABT_BIN_ROOT=$(WABT_SRC_ROOT)/$(WABT_BIN_CHOICE)

WASI_CLANG=$(WASI_SDK_ROOT)/bin/clang
WASI_SYSROOT=$(WASI_SDK_ROOT)/share/wasi-sysroot

#CFLAGS for compiling files to play nice with wasm2c and hfi emulation
WASM_CFLAGS=-Wl,--export-all -Wl,--global-base=150000 -Wl,-z,stack-size=1048576 -Wl,--growable-table

WASM2C=$(WABT_BIN_ROOT)/wasm2c

WASM2C_RUNTIME_PATH=$(WABT_SRC_ROOT)/wasm2c/
WASM2C_RUNTIME_FILES=$(addprefix $(WASM2C_RUNTIME_PATH), wasm-rt-impl.c wasm-rt-os-unix.c uvwasi-rt.c) wasm-rt-runner-static.c
WASM2C_SHADOW_RUNTIME_FILES=$(addprefix $(WASM2C_RUNTIME_PATH), wasm-rt-shadow.cpp)

HFIPATH=$(WABT_SRC_ROOT)/wasm2c/examples/badoptexample/

UVWASI_PATH=$(WABT_SRC_ROOT)/third_party/uvwasi

INCS=-I$(UVWASI_PATH)/include -I$(WASM2C_RUNTIME_PATH) -I$(HFIPATH)
DEPS=-L$(WABT_BIN_ROOT)/_deps/libuv-build -L$(WABT_BIN_ROOT)/third_party/uvwasi

LIBS=-luvwasi_a -luv -lpthread

ALL_RESULTS=rlbox

all: wasmrt $(ALL_RESULTS)

$(WABT_BIN_ROOT):
	cd $(WABT_SRC_ROOT)/mybuild && make ../$(WABT_BIN_CHOICE)

wasmrt: $(WABT_BIN_ROOT)
	cd $(WABT_SRC_ROOT) && make update-wasm2c
	cd $(WABT_BIN_ROOT) && make -j$(shell nproc)

clean:
	rm -rf $(ALL_RESULTS) *.o

rlbox: rlbox.wasm.c $(WASM2C_RUNTIME_FILES)
	clang++ -O3 -c $(WASM_SECURITY_FLAGS) $(WASM2C_SHADOW_RUNTIME_FILES) $(INCS)
	clang   -O3 -c $(WASM_SECURITY_FLAGS) ./rlbox.wasm.c $(WASM2C_RUNTIME_FILES) $(INCS)
	clang++ -O3 $(WASM_SECURITY_FLAGS) *.o -o rlbox $(DEPS) $(LIBS)

run: rlbox
	$(PWD)/rlbox

run-gdb: rlbox
	gdb --args $(PWD)/rlbox

run-rr: rlbox
	rr record $(PWD)/rlbox
