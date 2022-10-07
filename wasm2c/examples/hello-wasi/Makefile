#assumes wasi-sdk installed system wide in default location
WASI_SDK_ROOT=/opt/wasi-sdk
WABT_ROOT=../../..

WASI_CLANG=$(WASI_SDK_ROOT)/bin/clang
WASI_SYSROOT=$(WASI_SDK_ROOT)/share/wasi-sysroot
WASM2C_RUNNER=$(WABT_ROOT)/bin/wasm2c-runner

#CFLAGS for compiling files to place nice with wasm2c
WASM_CFLAGS=-Wl,--export-all


WASM2C=$(WABT_ROOT)/bin/wasm2c

WASM2C_RUNTIME_PATH=$(WABT_ROOT)/wasm2c/
WASM2C_RUNTIME_FILES=$(addprefix $(WASM2C_RUNTIME_PATH), wasm-rt-impl.c wasm-rt-os-unix.c uvwasi-rt.c)

UVWASI_PATH=$(WABT_ROOT)/third_party/uvwasi

DEPS=-I$(UVWASI_PATH)/include -L$(WABT_ROOT)/build/_deps/libuv-build -L$(WABT_ROOT)/build/third_party/uvwasi

LIBS=-luvwasi_a -luv -lpthread

ALL_RESULTS=hello.wasm hello.wasm.c hello.so

all: $(ALL_RESULTS)

clean:
	rm -rf $(ALL_RESULTS) hello.wasm.h *.o

hello.wasm: hello.c
	$(WASI_CLANG) --sysroot $(WASI_SYSROOT) $(WASM_CFLAGS) hello.c -o hello.wasm

hello.wasm.c: hello.wasm
	$(WASM2C) hello.wasm -o hello.wasm.c

hello.so: hello.wasm.c $(WASM2C_RUNTIME_FILES)
	$(CC) -shared -fPIC hello.wasm.c -o hello.so -I$(WASM2C_RUNTIME_PATH) $(WASM2C_RUNTIME_FILES) $(DEPS) $(LIBS)

run: hello.so
	$(WASM2C_RUNNER) $(PWD)/hello.so

