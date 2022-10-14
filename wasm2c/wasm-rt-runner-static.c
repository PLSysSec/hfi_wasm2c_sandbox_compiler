#if defined(_WIN32)
// Remove warnings for strcat, strcpy as they are safely used here
#define _CRT_SECURE_NO_WARNINGS
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wasm-rt.h"
#ifndef WASM_NO_UVWASI
#include "uvwasi.h"
#endif

#if defined(_WIN32)
#define LINETERM "\r\n"
#else
#define LINETERM "\n"
#endif

#ifndef WASM_NO_UVWASI
void init_uvwasi_local(uvwasi_t * local_uvwasi_state, int argc, char const * argv[])
{
    uvwasi_options_t init_options;

    //pass in standard descriptors
    init_options.in = 0;
    init_options.out = 1;
    init_options.err = 2;
    init_options.fd_table_size = 3;

    //pass in args and environement
    extern const char ** environ;
    init_options.argc = argc;
    init_options.argv = argv;
    init_options.envp = (const char **) environ;

    //no sandboxing enforced, binary has access to everything user does
    init_options.preopenc = 2;
    init_options.preopens = calloc(2, sizeof(uvwasi_preopen_t));

    init_options.preopens[0].mapped_path = "/";
    init_options.preopens[0].real_path = "/";
    init_options.preopens[1].mapped_path = "./";
    init_options.preopens[1].real_path = ".";

    init_options.allocator = NULL;

    uvwasi_errno_t ret = uvwasi_init(local_uvwasi_state, &init_options);

    if (ret != UVWASI_ESUCCESS) {
        printf("uvwasi_init failed with error %d\n", ret);
        exit(1);
    }
}
#endif

void wasm_rt_sys_init();
wasm2c_sandbox_funcs_t get_wasm2c_sandbox_info();
void w2c__start(void* sbx);

int main(int argc, char const* argv[]) {
  #ifdef HFI_EMULATION
  wasm_rt_hfi_emulate_reserve_lower4();
  #endif

  wasm_rt_sys_init();

  wasm2c_sandbox_funcs_t sandbox_info = get_wasm2c_sandbox_info();

  const uint32_t dont_override_heap_size = 0;
  void* sandbox = sandbox_info.create_wasm2c_sandbox(dont_override_heap_size);
  if (!sandbox) {
    printf("Error: Could not create sandbox" LINETERM);
    exit(1);
  }

#ifdef WASM_USE_HFI
  wasm_rt_memory_t* memory = sandbox_info.get_wasm2c_memory(sandbox);
  wasm_rt_hfi_enable(memory);
#endif

#ifndef WASM_NO_UVWASI
  uvwasi_t local_uvwasi_state;
  init_uvwasi_local(&local_uvwasi_state, argc, argv);
  sandbox_info.init_uvwasi_state(sandbox, &local_uvwasi_state);
#endif

  sandbox_info.init_wasm2c_sandbox(sandbox);
  w2c__start(sandbox);

#ifdef WASM_USE_HFI
  wasm_rt_hfi_disable();
#endif

  return 0;
}
