#if defined(_WIN32)
// Remove warnings for strcat, strcpy as they are safely used here
#define _CRT_SECURE_NO_WARNINGS
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wasm-rt.h"
#ifndef WASM_NO_UVWASI
#include "uv-wasi-setup.inc.c"
#endif

#if defined(_WIN32)
#define LINETERM "\r\n"
#else
#define LINETERM "\n"
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
