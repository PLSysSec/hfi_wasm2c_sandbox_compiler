/*
 * Copyright 2018 WebAssembly Community Group participants
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "wasm-rt-os.h"
#include "wasm-rt.h"

#include <assert.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#ifdef WASM_RT_CUSTOM_TRAP_HANDLER
// forward declare the signature of any custom trap handler
void WASM_RT_CUSTOM_TRAP_HANDLER(const char*);
#endif

void wasm_rt_trap(wasm_rt_trap_t code) {
  const char* error_message = "wasm2c: unknown trap";
  switch (code) {
    case WASM_RT_TRAP_NONE: {
      // this should never happen
      error_message = "wasm2c: WASM_RT_TRAP_NONE";
      break;
    }
    case WASM_RT_TRAP_OOB: {
      error_message = "wasm2c: WASM_RT_TRAP_OOB";
      break;
    }
    case WASM_RT_TRAP_INT_OVERFLOW: {
      error_message = "wasm2c: WASM_RT_TRAP_INT_OVERFLOW";
      break;
    }
    case WASM_RT_TRAP_DIV_BY_ZERO: {
      error_message = "wasm2c: WASM_RT_TRAP_DIV_BY_ZERO";
      break;
    }
    case WASM_RT_TRAP_INVALID_CONVERSION: {
      error_message = "wasm2c: WASM_RT_TRAP_INVALID_CONVERSION";
      break;
    }
    case WASM_RT_TRAP_UNREACHABLE: {
      error_message = "wasm2c: WASM_RT_TRAP_UNREACHABLE";
      break;
    }
    case WASM_RT_TRAP_CALL_INDIRECT_TABLE_EXPANSION: {
      error_message = "wasm2c: WASM_RT_TRAP_CALL_INDIRECT_TABLE_EXPANSION";
      break;
    }
    case WASM_RT_TRAP_CALL_INDIRECT_OOB_INDEX: {
      error_message = "wasm2c: WASM_RT_TRAP_CALL_INDIRECT_OOB_INDEX";
      break;
    }
    case WASM_RT_TRAP_CALL_INDIRECT_NULL_PTR: {
      error_message = "wasm2c: WASM_RT_TRAP_CALL_INDIRECT_NULL_PTR";
      break;
    }
    case WASM_RT_TRAP_CALL_INDIRECT_TYPE_MISMATCH: {
      error_message = "wasm2c: WASM_RT_TRAP_CALL_INDIRECT_TYPE_MISMATCH";
      break;
    }
    case WASM_RT_TRAP_CALL_INDIRECT_UNKNOWN_ERR: {
      error_message = "wasm2c: WASM_RT_TRAP_CALL_INDIRECT_UNKNOWN_ERR";
      break;
    }
    case WASM_RT_TRAP_EXHAUSTION: {
      error_message = "wasm2c: WASM_RT_TRAP_EXHAUSTION";
      break;
    }
    case WASM_RT_TRAP_SHADOW_MEM: {
      error_message = "wasm2c: WASM_RT_TRAP_SHADOW_MEM";
      break;
    }
    case WASM_RT_TRAP_WASI: {
      error_message = "wasm2c: WASM_RT_TRAP_WASI";
      break;
    }
  };
#ifdef WASM_RT_CUSTOM_TRAP_HANDLER
  WASM_RT_CUSTOM_TRAP_HANDLER(error_message);
#else
  fprintf(stderr, "Error: %s\n", error_message);
  abort();
#endif
}

void wasm_rt_callback_error_trap(wasm_rt_table_t* table,
                                 uint32_t func_index,
                                 uint32_t expected_func_type) {
  if (func_index >= table->size) {
    wasm_rt_trap(WASM_RT_TRAP_CALL_INDIRECT_OOB_INDEX);
  } else if (!table->data[func_index].func) {
    wasm_rt_trap(WASM_RT_TRAP_CALL_INDIRECT_NULL_PTR);
  } else if (table->data[func_index].func_type != expected_func_type) {
    wasm_rt_trap(WASM_RT_TRAP_CALL_INDIRECT_TYPE_MISMATCH);
  }
  wasm_rt_trap(WASM_RT_TRAP_CALL_INDIRECT_UNKNOWN_ERR);
}

static bool func_types_are_equal(wasm_func_type_t* a, wasm_func_type_t* b) {
  if (a->param_count != b->param_count || a->result_count != b->result_count)
    return 0;
  uint32_t i;
  for (i = 0; i < a->param_count; ++i)
    if (a->params[i] != b->params[i])
      return 0;
  for (i = 0; i < a->result_count; ++i)
    if (a->results[i] != b->results[i])
      return 0;
  return 1;
}

uint32_t wasm_rt_register_func_type(wasm_func_type_t** p_func_type_structs,
                                    uint32_t* p_func_type_count,
                                    uint32_t param_count,
                                    uint32_t result_count,
                                    wasm_rt_type_t* types) {
  wasm_func_type_t func_type;

  func_type.param_count = param_count;
  if (func_type.param_count != 0) {
    func_type.params = malloc(param_count * sizeof(wasm_rt_type_t));
    assert(func_type.params != 0);
  } else {
    func_type.params = 0;
  }

  func_type.result_count = result_count;
  if (func_type.result_count != 0) {
    func_type.results = malloc(result_count * sizeof(wasm_rt_type_t));
    assert(func_type.results != 0);
  } else {
    func_type.results = 0;
  }

  uint32_t i;
  for (i = 0; i < param_count; ++i)
    func_type.params[i] = types[i];
  for (i = 0; i < result_count; ++i)
    func_type.results[i] = types[(uint64_t)(param_count) + i];

  for (i = 0; i < *p_func_type_count; ++i) {
    wasm_func_type_t* func_types = *p_func_type_structs;
    if (func_types_are_equal(&func_types[i], &func_type)) {
      if (func_type.params) {
        free(func_type.params);
      }
      if (func_type.results) {
        free(func_type.results);
      }
      return i + 1;
    }
  }

  uint32_t idx = (*p_func_type_count)++;
  // realloc works fine even if *p_func_type_structs is null
  *p_func_type_structs = realloc(*p_func_type_structs,
                                 *p_func_type_count * sizeof(wasm_func_type_t));
  (*p_func_type_structs)[idx] = func_type;
  return idx + 1;
}

void wasm_rt_cleanup_func_types(wasm_func_type_t** p_func_type_structs,
                                uint32_t* p_func_type_count) {
  // Use a u64 to iterate over u32 arrays to prevent infinite loops
  const uint32_t func_count = *p_func_type_count;
  for (uint64_t idx = 0; idx < func_count; idx++) {
    wasm_func_type_t* func_type = &((*p_func_type_structs)[idx]);
    if (func_type->params != 0) {
      free(func_type->params);
      func_type->params = 0;
    }
    if (func_type->results != 0) {
      free(func_type->results);
      func_type->results = 0;
    }
  }
  free(*p_func_type_structs);
}

#ifdef HFI_EMULATION
static int hfi_emulate_reserved_lower_4 = 0;

static void check_if_hfi_emulate_reserved_lower_4_has_run() {
  // If lower 4GB is reserved we should be able to access it
  // access some pages in the lower 4GB below
  uint64_t* a = (uint64_t*) 0x12345600;
  uint64_t* b = (uint64_t*) 0x5ffffff0;
  if (*a != 0 || *b != 0) {
    printf("Error: Lower 4GB not zero initialized");
    abort();
  }
}

#endif

#ifdef WASM_USE_MASKING
static int is_power_of_two(uint64_t x) {
  return ((x != 0) && !(x & (x - 1)));
}
#endif

#define WASM_PAGE_SIZE 65536

// 64 bit machine
#if UINTPTR_MAX == 0xffffffffffffffff

#ifdef WASM_USE_GUARD_PAGES
// Guard page of 4GiB
# define WASM_HEAP_GUARD_PAGE_SIZE 0x100000000ull
#else
# define WASM_HEAP_GUARD_PAGE_SIZE 0
#endif

// Heap aligned to 4GB
#define WASM_HEAP_ALIGNMENT 0x100000000ull
// By default max heap is 4GB
#define WASM_HEAP_DEFAULT_MAX_PAGES 65536
// Runtime can override the max heap up to 4GB
#define WASM_HEAP_MAX_ALLOWED_PAGES 65536

// 32 bit machine
#elif UINTPTR_MAX == 0xffffffff

// No guard pages
#define WASM_HEAP_GUARD_PAGE_SIZE 0
// Unaligned heap
#define WASM_HEAP_ALIGNMENT 0
// Default max heap is 16MB (1GB if you enable incremental heaps)
#ifdef WASM_USE_INCREMENTAL_MOVEABLE_MEMORY_ALLOC
#define WASM_HEAP_DEFAULT_MAX_PAGES 16384
#else
#define WASM_HEAP_DEFAULT_MAX_PAGES 256
#endif
// Runtime can override the max heap up to 1GB
#define WASM_HEAP_MAX_ALLOWED_PAGES 16384
#else
#error "Unknown pointer size"
#endif

uint64_t wasm_rt_get_default_max_linear_memory_size() {
  uint64_t ret = ((uint64_t)WASM_HEAP_DEFAULT_MAX_PAGES) * WASM_PAGE_SIZE;
  return ret;
}

static uint64_t compute_heap_reserve_space(uint32_t chosen_max_pages) {
  const uint64_t heap_reserve_size =
      ((uint64_t)chosen_max_pages) * WASM_PAGE_SIZE + WASM_HEAP_GUARD_PAGE_SIZE;
  return heap_reserve_size;
}

bool wasm_rt_allocate_memory(wasm_rt_memory_t* memory,
                             uint32_t initial_pages,
                             uint32_t max_pages) {
  const uint32_t byte_length = initial_pages * WASM_PAGE_SIZE;

  uint32_t chosen_max_pages = 0;
  if (max_pages == 0) {
#define MAX_MACRO(a,b) (((a)>(b))?(a):(b))
    chosen_max_pages = MAX_MACRO(initial_pages, WASM_HEAP_DEFAULT_MAX_PAGES);
#undef MAX_MACRO
  } else if (max_pages > WASM_HEAP_MAX_ALLOWED_PAGES) {
    chosen_max_pages = WASM_HEAP_MAX_ALLOWED_PAGES;
  } else {
    chosen_max_pages = max_pages;
  }

#ifdef HFI_EMULATION
  const uint64_t hfi_emulation_max_pages = ((uint64_t)wasm_rt_hfi_emulate_reserve_lower4_end()) / WASM_PAGE_SIZE;
  if (chosen_max_pages > hfi_emulation_max_pages) {
    chosen_max_pages = hfi_emulation_max_pages;
  }
#endif

  if (chosen_max_pages < initial_pages) {
    return false;
  }

#ifdef WASM_USE_MMAP
  void* addr = NULL;
  const uint64_t retries = 10;
  const uint64_t heap_reserve_size =
      compute_heap_reserve_space(chosen_max_pages);

  // masking for sandboxing requires the heap reserve size to always be a power of 2
# ifdef WASM_USE_MASKING
    if (!is_power_of_two(heap_reserve_size)) {
      return false;
    }
# endif

# ifdef WASM_USE_HFI
  // HFI precommits all memory, as HFI will ensure wasm trapping semantics
  // Since mmap is lazy, this does not increase memory consumption
  // The advantage is that wasm_grow does not have to call mprotect; it just changes the hfi config
  int prot_flags = MMAP_PROT_READ | MMAP_PROT_WRITE;
# else
  int prot_flags = MMAP_PROT_NONE;
# endif

# ifdef HFI_EMULATION2
  int mmap_fixed_flag = MMAP_MAP_FIXED_NOREPLACE;
#endif

  for (uint64_t i = 0; i < retries; i++) {
# ifdef HFI_EMULATION2
    addr =
        os_mmap((void*) hfi_emulate2_memory_start(), heap_reserve_size, prot_flags, MMAP_MAP_FIXED_NOREPLACE);
    if (addr && addr != (void*) hfi_emulate2_memory_start()) {
      if (mmap_fixed_flag == MMAP_MAP_FIXED_NOREPLACE) {
        printf("Warning: Mismatched HFI_EMULATION2 mode address: Got %p, Expected %p. Switching to MAP_FIXED\n",
          addr, (void*) hfi_emulate2_memory_start());
        mmap_fixed_flag = MMAP_MAP_FIXED;
        os_munmap(addr, heap_reserve_size);
        addr = NULL;
      } else {
        printf("Error: Mismatched HFI_EMULATION2 mode address: Got %p, Expected %p. \n",
          addr, (void*) hfi_emulate2_memory_start());
        abort();
      }
    }
#else
    addr =
        os_mmap_aligned(NULL, heap_reserve_size, prot_flags, MMAP_MAP_NONE,
                        WASM_HEAP_ALIGNMENT, 0 /* alignment_offset */);
#endif
    if (addr) {
      break;
    }
  }
#ifdef HFI_EMULATION
  memory->allocated_dummy = addr;
  addr = 0;
#else
  if (!addr) {
    os_print_last_error("os_mmap failed.");
    return false;
  }
#endif

# ifndef WASM_USE_HFI
  int ret = os_mmap_commit(addr, byte_length, MMAP_PROT_READ | MMAP_PROT_WRITE);
  if (ret != 0) {
    return false;
  }
# endif

  // Compute the mask for sandboxing.
# ifdef WASM_USE_MASKING
  *(uint32_t*)&memory->mem_mask = heap_reserve_size - 1;
# endif

  // This is a valid way to initialize a constant field that is not undefined
  // behavior
  // https://stackoverflow.com/questions/9691404/how-to-initialize-const-in-a-struct-in-c-with-malloc
  // Summary: malloc of a struct, followed by a write to the constant fields is
  // still defined behavior iff
  //   there is no prior read of the field
  *(uint8_t**)&memory->data = addr;
#else
  // malloc based heaps
# ifdef WASM_USE_MALLOC_MOVABLE
    memory->data = calloc(byte_length, 1);
# else
    const uint64_t heap_max_size = ((uint64_t)chosen_max_pages) * WASM_PAGE_SIZE;
    *(uint8_t**)&memory->data = calloc(heap_max_size, 1);
# endif

#endif

  memory->size = byte_length;
  memory->pages = initial_pages;
  memory->max_pages = chosen_max_pages;

#if defined(WASM_CHECK_SHADOW_MEMORY)
  wasm2c_shadow_memory_create(memory);
#endif

#ifdef WASM_USE_HFI
  hfi_sandbox* hfi_config = &(memory->hfi_config);
  memset(hfi_config, 0, sizeof(hfi_sandbox));
  hfi_config->is_trusted_sandbox = true;
  hfi_config->data_ranges[0].base_address = (uintptr_t) memory->data;
  // wasm page size is a multiple of 64k, so this satisfies the hfi constraint that size has to be a multiple of 64k
  hfi_config->data_ranges[0].offset_limit = memory->size;
  hfi_config->data_ranges[0].readable = true;
  hfi_config->data_ranges[0].writeable = true;
  hfi_config->data_ranges[0].range_size_type = (uint8_t) HFI_RANGE_SIZE_TYPE_LARGE;
  // TODO: code range
  hfi_config->code_ranges[0].executable = true;

# ifdef HFI_EMULATION
    if(hfi_emulate_reserved_lower_4 == 0) {
      check_if_hfi_emulate_reserved_lower_4_has_run();
      hfi_emulate_reserved_lower_4 = 1;
    } else if(hfi_emulate_reserved_lower_4 == 2) {
      printf("Error: Cannot create more than one sandbox while in HFI_EMULATION mode.\n");
      abort();
    }

    hfi_emulate_reserved_lower_4 = 2;
# endif

#endif

  return true;
}

void wasm_rt_deallocate_memory(wasm_rt_memory_t* memory) {
#ifdef WASM_USE_MMAP
  const uint64_t heap_reserve_size =
      compute_heap_reserve_space(memory->max_pages);
# ifdef HFI_EMULATION
    os_munmap(memory->allocated_dummy, heap_reserve_size);
# else
    os_munmap(memory->data, heap_reserve_size);
# endif
#else
  free(memory->data);
#endif

#if defined(WASM_CHECK_SHADOW_MEMORY)
  wasm2c_shadow_memory_destroy(memory);
#endif

#ifdef HFI_EMULATION
  if(hfi_emulate_reserved_lower_4 != 2) {
    printf("Error: Unexpected value for hfi_emulate_reserved_lower_4.\n");
    abort();
  }

  void* page_addr = (void*) wasm_rt_hfi_emulate_reserve_lower4_start();
  const uint64_t alloc_size = ((uint64_t) wasm_rt_hfi_emulate_reserve_lower4_end()) - wasm_rt_hfi_emulate_reserve_lower4_start();
  memset(page_addr, 0, alloc_size);

  hfi_emulate_reserved_lower_4 = 1;
#endif
}

uint32_t wasm_rt_grow_memory(wasm_rt_memory_t* memory, uint32_t delta) {
  uint32_t old_pages = memory->pages;
  uint32_t new_pages = memory->pages + delta;
  if (new_pages == 0) {
    return 0;
  }
  if (new_pages < old_pages || new_pages > memory->max_pages) {
    return (uint32_t)-1;
  }
  uint32_t old_size = old_pages * WASM_PAGE_SIZE;
  uint32_t new_size = new_pages * WASM_PAGE_SIZE;
  uint32_t delta_size = delta * WASM_PAGE_SIZE;

#ifdef WASM_USE_MMAP

# ifndef WASM_USE_HFI
    // mmap based heaps with guard pages
    int ret = os_mmap_commit(memory->data + old_size, delta_size,
                            MMAP_PROT_READ | MMAP_PROT_WRITE);
    if (ret != 0) {
      return (uint32_t)-1;
    }

# endif

#else
  // malloc based heaps --- if below macro is not defined, the max memory range
  // is already allocated
# ifdef WASM_USE_MALLOC_MOVABLE
    uint8_t* new_data = realloc(memory->data, new_size);
    if (new_data == NULL) {
      return (uint32_t)-1;
    }
#   if !WABT_BIG_ENDIAN
      memset(new_data + old_size, 0, delta_size);
#   endif
    memory->data = new_data;
# endif
#endif

#if WABT_BIG_ENDIAN
  memmove(memory->data + new_size - old_size, memory->data, old_size);
  memset(memory->data, 0, delta_size);
#endif
  memory->pages = new_pages;
  memory->size = new_size;
#if defined(WASM_CHECK_SHADOW_MEMORY)
  wasm2c_shadow_memory_expand(memory);
#endif

#ifdef WASM_USE_HFI
  // wasm page size is a multiple of 64k, so this satisfies the hfi constraint that size has to be a multiple of 64k
  memory->hfi_config.data_ranges[0].offset_limit = memory->size;
  wasm_rt_hfi_enable(memory);
#endif

  return old_pages;
}

void wasm_rt_allocate_table(wasm_rt_table_t* table,
                            uint32_t elements,
                            uint32_t max_elements) {
  assert(max_elements >= elements);
  table->size = elements;
  table->max_size = max_elements;
  table->data = calloc(table->size, sizeof(wasm_rt_elem_t));
  assert(table->data != 0);
}

void wasm_rt_deallocate_table(wasm_rt_table_t* table) {
  free(table->data);
}

#define WASM_SATURATING_U32_ADD(ret_ptr, a, b) \
  {                                            \
    if ((a) > (UINT32_MAX - (b))) {            \
      /* add will overflowed */                \
      *ret_ptr = UINT32_MAX;                   \
    } else {                                   \
      *ret_ptr = (a) + (b);                    \
    }                                          \
  }

#define WASM_CHECKED_U32_RET_SIZE_T_MULTIPLY(ret_ptr, a, b)     \
  {                                                             \
    if ((a) > (SIZE_MAX / (b))) {                               \
      /* multiple will overflowed */                            \
      wasm_rt_trap(WASM_RT_TRAP_CALL_INDIRECT_TABLE_EXPANSION); \
    } else {                                                    \
      /* convert to size by assigning */                        \
      *ret_ptr = a;                                             \
      *ret_ptr = *ret_ptr * b;                                  \
    }                                                           \
  }

void wasm_rt_expand_table(wasm_rt_table_t* table) {
  uint32_t new_size = 0;
  WASM_SATURATING_U32_ADD(&new_size, table->size, 32);

  if (new_size > table->max_size) {
    new_size = table->max_size;
  }

  if (table->size == new_size) {
    // table is already as large as we allowed, can't expand further
    wasm_rt_trap(WASM_RT_TRAP_CALL_INDIRECT_TABLE_EXPANSION);
  }

  size_t allocation_size = 0;
  WASM_CHECKED_U32_RET_SIZE_T_MULTIPLY(&allocation_size, sizeof(wasm_rt_elem_t),
                                       new_size);
  table->data = realloc(table->data, allocation_size);
  assert(table->data != 0);

  memset(&(table->data[table->size]), 0,
         allocation_size - (table->size * sizeof(wasm_rt_elem_t)));
  table->size = new_size;
}

void wasm2c_ensure_linked() {
  // We use this to ensure the dynamic library with the wasi symbols is loaded
  // for the host application
}

void wasm2c_configuration_check(wasm2c_configuration* code_config, size_t config_size) {

  if (config_size != sizeof(wasm2c_configuration)) {
    printf("wasm2c code configuration size does not match wasm2c runtime configuration size: %zu, %zu\n", config_size, sizeof(wasm2c_configuration));
    abort();
  }

  wasm2c_configuration runtime_config = wasm2c_configuration_init();
  int different = memcmp(code_config, &runtime_config, config_size);

  if (different) {
    printf("wasm2c code configuration does not match wasm2c runtime configuration\n");
    uint8_t* code_config_ptr = (uint8_t*) code_config;
    uint8_t* runtime_config_ptr = (uint8_t*) &runtime_config;

    for(size_t i = 0; i < sizeof(wasm2c_configuration); i++) {
      printf("Byte %zu" "(Code: %" PRIu8 " : Runtime: %" PRIu8 ")", i, code_config_ptr[i], runtime_config_ptr[i]);
      wasm2c_memory_check((wasm_rt_memory_t*) 0x123400);
    }

    abort();
  }
}

__attribute__((noinline))
void wasm2c_memory_check(wasm_rt_memory_t* mem) {
  bool found = false;
  for(uint64_t i = 0; i < mem->size; i++) {
    if(mem->data[i] != 0) {
      found = true;
      printf("Byte %" PRIu64 " is non zero.\n", i);
      break;
    }
  }
  if (!found) {
    printf("All bytes zero\n");
  }
}

#undef WASM_PAGE_SIZE
#undef WASM_HEAP_GUARD_PAGE_SIZE
#undef WASM_HEAP_ALIGNMENT
#undef WASM_HEAP_DEFAULT_MAX_PAGES
#undef WASM_HEAP_MAX_ALLOWED_PAGES
#undef WASM_SATURATING_U32_ADD
#undef WASM_CHECKED_U32_RET_SIZE_T_MULTIPLY
