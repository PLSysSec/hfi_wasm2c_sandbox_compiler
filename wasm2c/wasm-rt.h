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

#ifndef WASM_RT_H_
#define WASM_RT_H_

#include <setjmp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifndef WASM_NO_UVWASI
#include "uvwasi.h"
#endif

#ifdef WASM_USE_HFI
#include "hfi.h"
#endif

#ifdef HFI_EMULATION
#include <sys/mman.h>
#endif

#if defined(_WIN32)
#define WASM2C_FUNC_EXPORT __declspec(dllexport)
#else
#define WASM2C_FUNC_EXPORT
#endif

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum stack depth before trapping. This can be configured by defining
 * this symbol before including wasm-rt when building the generated c files,
 * for example:
 *
 * ```
 *   cc -c -DWASM_RT_MAX_CALL_STACK_DEPTH=100 my_module.c -o my_module.o
 * ```
 * */
#ifndef WASM_RT_MAX_CALL_STACK_DEPTH
#define WASM_RT_MAX_CALL_STACK_DEPTH 500
#endif

// One of the following has to be defined
//
// WASM_USE_GUARD_PAGES
// WASM_USE_BOUNDS_CHECKS
// WASM_USE_HFI
// WASM_USE_MASKING

#if !defined(WASM_USE_GUARD_PAGES) && !defined(WASM_USE_BOUNDS_CHECKS) && !defined(WASM_USE_MASKING) && !defined(WASM_USE_HFI) && !defined(WASM_USE_SEGMENT) && !defined(WASM_USE_CHERI)

#error "Must define one of [WASM_USE_GUARD_PAGES, WASM_USE_BOUNDS_CHECKS, WASM_USE_MASKING, WASM_USE_HFI, WASM_USE_CHERI]"

#elif defined(WASM_USE_HFI) && (defined(WASM_USE_GUARD_PAGES) || defined(WASM_USE_BOUNDS_CHECKS) || defined(WASM_USE_MASKING) || defined(WASM_USE_SEGMENT) || defined(WASM_USE_CHERI))

#error "Cannot define multiple in [WASM_USE_GUARD_PAGES, WASM_USE_BOUNDS_CHECKS, WASM_USE_MASKING, WASM_USE_HFI]"

// To irritating to check all combinations, but only one of the above should be defined

#endif

// One of the following memory allocation strategies need to be used
//
// WASM_USE_MMAP
// WASM_USE_MALLOC_IMMOVABLE
// WASM_USE_MALLOC_MOVABLE
//
// defaults to WASM_USE_MMAP

#if !defined(WASM_USE_MMAP) && !defined(WASM_USE_MALLOC_IMMOVABLE) && !defined(WASM_USE_MALLOC_MOVABLE)
#define WASM_USE_MMAP
#endif

#if defined(WASM_USE_MASKING) && !defined(WASM_USE_MMAP)
#error "Masking must use WASM_USE_MMAP"
#endif

#if defined(WASM_USE_GUARD_PAGES) && UINTPTR_MAX == 0xffffffff
#error "Guard pages not supported on 32 bit machines"
#endif

#if defined(_MSC_VER)
#define WASM_RT_NO_RETURN __declspec(noreturn)
#else
#define WASM_RT_NO_RETURN __attribute__((noreturn))
#endif

/** Reason a trap occurred. Provide this to `wasm_rt_trap`.
 * If you update this enum also update the error message in wasm_rt_trap.
 */
typedef enum {
  WASM_RT_TRAP_NONE,         /** No error. */
  WASM_RT_TRAP_OOB,          /** Out-of-bounds access in linear memory. */
  WASM_RT_TRAP_INT_OVERFLOW, /** Integer overflow on divide or truncation. */
  WASM_RT_TRAP_DIV_BY_ZERO,  /** Integer divide by zero. */
  WASM_RT_TRAP_INVALID_CONVERSION, /** Conversion from NaN to integer. */
  WASM_RT_TRAP_UNREACHABLE,        /** Unreachable instruction executed. */
  WASM_RT_TRAP_CALL_INDIRECT_TABLE_EXPANSION, /** Invalid call_indirect, as func
                                                 table cannot grow/grow further.
                                               */
  WASM_RT_TRAP_CALL_INDIRECT_OOB_INDEX, /** Invalid call_indirect, due to index
                                           larger than func table. */
  WASM_RT_TRAP_CALL_INDIRECT_NULL_PTR,  /** Invalid call_indirect, as function
                                           being invoked is null. */
  WASM_RT_TRAP_CALL_INDIRECT_TYPE_MISMATCH, /** Invalid call_indirect, as
                                               function being invoked has an
                                               unexpected type. */
  WASM_RT_TRAP_CALL_INDIRECT_UNKNOWN_ERR,   /** Invalid call_indirect, for other
                                               reason. */
  WASM_RT_TRAP_EXHAUSTION,                  /** Call stack exhausted. */
  WASM_RT_TRAP_SHADOW_MEM, /** Trap due to shadow memory mismatch */
  WASM_RT_TRAP_WASI,       /** Trap due to WASI error */
} wasm_rt_trap_t;

/** Value types. Used to define function signatures. */
typedef enum {
  WASM_RT_I32,
  WASM_RT_I64,
  WASM_RT_F32,
  WASM_RT_F64,
} wasm_rt_type_t;

/** A function type for all `anyfunc` functions in a Table. All functions are
 * stored in this canonical form, but must be cast to their proper signature to
 * call. */
typedef void (*wasm_rt_anyfunc_t)(void);

/**
 * The class of the indirect function being invoked
 */
typedef enum {
  WASM_RT_INTERNAL_FUNCTION,
  WASM_RT_EXTERNAL_FUNCTION
} wasm_rt_elem_target_class_t;

/** A single element of a Table. */
typedef struct {
  wasm_rt_elem_target_class_t func_class;
  /** The index as returned from `wasm_rt_register_func_type`. */
  uint32_t func_type;
  /** The function. The embedder must know the actual C signature of the
   * function and cast to it before calling. */
  wasm_rt_anyfunc_t func;
} wasm_rt_elem_t;

typedef uint8_t wasm2c_shadow_memory_cell_t;

typedef struct {
  wasm2c_shadow_memory_cell_t* data;
  size_t data_size;
  void* allocation_sizes_map;
  uint32_t heap_base;
#ifdef WASM_CHECK_SHADOW_MEMORY_LOG
  FILE* log_fp;
#endif
} wasm2c_shadow_memory_t;

/** A Memory object. */
typedef struct {
  /** The linear memory data, with a byte length of `size`. */
#ifdef WASM_USE_CHERI
  #include <cheriintrin.h>
  #include <cheri.h>
  uint8_t* __capability data;
  #ifdef WASM_USE_MALLOC_MOVABLE
    static_assert(false && "malloc_movable is not compatible with Cheri mode");
  #endif
#else
  #ifdef WASM_USE_MALLOC_MOVABLE
    uint8_t* data;
  #else
    uint8_t* const data;
  #endif
#endif
  /** The current and maximum page count for this Memory object. If there is no
   * maximum, `max_pages` is 0xffffffffu (i.e. UINT32_MAX). */
  uint32_t pages, max_pages;
  /** The current size of the linear memory, in bytes. */
  uint32_t size;

  /** This sets the mask, which is computed based on the heap size */
#ifdef WASM_USE_MASKING
  const uint32_t mem_mask;
#endif

#if defined(WASM_CHECK_SHADOW_MEMORY)
  wasm2c_shadow_memory_t shadow_memory;
#endif
#ifdef WASM_USE_HFI
  hfi_sandbox hfi_config;
#endif
#ifdef HFI_EMULATION
  uint8_t* allocated_dummy;
#endif
} wasm_rt_memory_t;

/** A Table object. */
typedef struct {
  /** The table element data, with an element count of `size`. */
  wasm_rt_elem_t* data;
  /** The maximum element count of this Table object. If there is no maximum,
   * `max_size` is 0xffffffffu (i.e. UINT32_MAX). */
  uint32_t max_size;
  /** The current element count of the table. */
  uint32_t size;
} wasm_rt_table_t;

typedef struct wasm_func_type_t {
  wasm_rt_type_t* params;
  wasm_rt_type_t* results;
  uint32_t param_count;
  uint32_t result_count;
} wasm_func_type_t;

#define WASM2C_WASI_MAX_SETJMP_STACK 32
#define WASM2C_WASI_MAX_FDS 32
typedef struct wasm_sandbox_wasi_data {
  wasm_rt_memory_t* heap_memory;
#ifndef WASM_NO_UVWASI
  uvwasi_t * uvwasi;
#endif

  uint32_t tempRet0;

  uint32_t next_setjmp_index;
  jmp_buf setjmp_stack[WASM2C_WASI_MAX_SETJMP_STACK];

  uint32_t main_argc;
  char** main_argv;

  int wasm_fd_to_native[WASM2C_WASI_MAX_FDS];
  uint32_t next_wasm_fd;

  void* clock_data;

} wasm_sandbox_wasi_data;

typedef void (*wasm_rt_sys_init_t)(void);
typedef void* (*create_wasm2c_sandbox_t)(uint32_t max_wasm_pages);
typedef void (*destroy_wasm2c_sandbox_t)(void* sbx_ptr);
#ifndef WASM_NO_UVWASI
typedef void (*init_uvwasi_state_t)(void* sbx_ptr, uvwasi_t *);
#endif
typedef void* (*lookup_wasm2c_nonfunc_export_t)(void* sbx_ptr,
                                                const char* name);
typedef uint32_t (*lookup_wasm2c_func_index_t)(void* sbx_ptr,
                                               uint32_t param_count,
                                               uint32_t result_count,
                                               wasm_rt_type_t* types);
typedef uint32_t (*add_wasm2c_callback_t)(
    void* sbx_ptr,
    uint32_t func_type_idx,
    void* func_ptr,
    wasm_rt_elem_target_class_t func_class);
typedef void (*remove_wasm2c_callback_t)(void* sbx_ptr, uint32_t callback_idx);
typedef wasm_rt_memory_t* (*get_wasm2c_memory_t)(void* sbx_ptr);
typedef void (*init_wasm2c_sandbox_t)(void* sbx_ptr);

typedef struct wasm2c_sandbox_funcs_t {
  wasm_rt_sys_init_t wasm_rt_sys_init;
  create_wasm2c_sandbox_t create_wasm2c_sandbox;
#ifndef WASM_NO_UVWASI
  init_uvwasi_state_t init_uvwasi_state;
#endif
  destroy_wasm2c_sandbox_t destroy_wasm2c_sandbox;
  lookup_wasm2c_nonfunc_export_t lookup_wasm2c_nonfunc_export;
  lookup_wasm2c_func_index_t lookup_wasm2c_func_index;
  add_wasm2c_callback_t add_wasm2c_callback;
  remove_wasm2c_callback_t remove_wasm2c_callback;
  get_wasm2c_memory_t get_wasm2c_memory;
  init_wasm2c_sandbox_t init_wasm2c_sandbox;
} wasm2c_sandbox_funcs_t;

/** Stop execution immediately and jump back to the call to `wasm_rt_try`.
 *  The result of `wasm_rt_try` will be the provided trap reason.
 *
 *  This is typically called by the generated code, and not the embedder. */
WASM_RT_NO_RETURN extern void wasm_rt_trap(wasm_rt_trap_t);

/** An indirect callback function failed.
 *  Deduce the reason for the failure and then call trap.
 *
 *  This is typically called by the generated code, and not the embedder. */
WASM_RT_NO_RETURN extern void wasm_rt_callback_error_trap(
    wasm_rt_table_t* table,
    uint32_t func_index,
    uint32_t expected_func_type);

/** Register a function type with the given signature. The returned function
 * index is guaranteed to be the same for all calls with the same signature.
 * The following varargs must all be of type `wasm_rt_type_t`, first the
 * params` and then the `results`.
 *
 *  ```
 *    // Register (func (param i32 f32) (result i64)).
 *    wasm_rt_register_func_type(2, 1, WASM_RT_I32, WASM_RT_F32, WASM_RT_I64);
 *    => returns 1
 *
 *    // Register (func (result i64)).
 *    wasm_rt_register_func_type(0, 1, WASM_RT_I32);
 *    => returns 2
 *
 *    // Register (func (param i32 f32) (result i64)) again.
 *    wasm_rt_register_func_type(2, 1, WASM_RT_I32, WASM_RT_F32, WASM_RT_I64);
 *    => returns 1
 *  ``` */
extern uint32_t wasm_rt_register_func_type(
    wasm_func_type_t** p_func_type_structs,
    uint32_t* p_func_type_count,
    uint32_t params,
    uint32_t results,
    wasm_rt_type_t* types);

extern void wasm_rt_cleanup_func_types(wasm_func_type_t** p_func_type_structs,
                                       uint32_t* p_func_type_count);

/**
 * Return the default value of the maximum size allowed for wasm memory.
 */
extern uint64_t wasm_rt_get_default_max_linear_memory_size();

/** Initialize a Memory object with an initial page size of `initial_pages` and
 * a maximum page size of `max_pages`.
 *
 *  ```
 *    wasm_rt_memory_t my_memory;
 *    // 1 initial page (65536 bytes), and a maximum of 2 pages.
 *    wasm_rt_allocate_memory(&my_memory, 1, 2);
 *  ``` */
extern bool wasm_rt_allocate_memory(wasm_rt_memory_t*,
                                    uint32_t initial_pages,
                                    uint32_t max_pages);

extern void wasm_rt_deallocate_memory(wasm_rt_memory_t*);

/** Grow a Memory object by `pages`, and return the previous page count. If
 * this new page count is greater than the maximum page count, the grow fails
 * and 0xffffffffu (UINT32_MAX) is returned instead.
 *
 *  ```
 *    wasm_rt_memory_t my_memory;
 *    ...
 *    // Grow memory by 10 pages.
 *    uint32_t old_page_size = wasm_rt_grow_memory(&my_memory, 10);
 *    if (old_page_size == UINT32_MAX) {
 *      // Failed to grow memory.
 *    }
 *  ``` */
extern uint32_t wasm_rt_grow_memory(wasm_rt_memory_t*, uint32_t pages);

#ifdef WASM_USE_HFI

#define wasm_rt_hfi_enable(memory) { hfi_set_sandbox_metadata(&(memory->hfi_config)); hfi_enter_sandbox(); }
#define wasm_rt_hfi_disable() { hfi_exit_sandbox(); }

#endif

/** Initialize a Table object with an element count of `elements` and a maximum
 * page size of `max_elements`.
 *
 *  ```
 *    wasm_rt_table_t my_table;
 *    // 5 elemnets and a maximum of 10 elements.
 *    wasm_rt_allocate_table(&my_table, 5, 10);
 *  ``` */
extern void wasm_rt_allocate_table(wasm_rt_table_t*,
                                   uint32_t elements,
                                   uint32_t max_elements);

extern void wasm_rt_deallocate_table(wasm_rt_table_t*);

extern void wasm_rt_expand_table(wasm_rt_table_t*);

#ifdef HFI_EMULATION
#define wasm_rt_hfi_emulate_reserve_lower4_start() 0x10000
#ifndef HFI_EMULATION_RR
#  define wasm_rt_hfi_emulate_reserve_lower4_end() 0x100000000
#else
   // Limit when running under the rr debugger.
#  define wasm_rt_hfi_emulate_reserve_lower4_end() 0x68000000
#endif

// HFI emulation requires the first 4gb for the wasm heap. This function reserves that range
#define wasm_rt_hfi_emulate_reserve_lower4() {                                                                  \
  /* The region 0x0 to wasm_rt_hfi_emulate_reserve_lower4_start is reserved by the OS */                        \
  /* Start after that */                                                                                        \
  void* page_addr = (void*) wasm_rt_hfi_emulate_reserve_lower4_start();                                         \
  const uint64_t alloc_size = ((uint64_t) wasm_rt_hfi_emulate_reserve_lower4_end()) -                           \
    wasm_rt_hfi_emulate_reserve_lower4_start();                                                                 \
                                                                                                                \
  void* addr = 0;                                                                                               \
  int mmap_fixed_flag = MAP_FIXED_NOREPLACE;                                                                    \
                                                                                                                \
  for (int retry = 0; retry < 10; retry++) {                                                                    \
                                                                                                                \
    addr = mmap(                                                                                                \
      page_addr,                                                                                                \
      alloc_size,                                                                                               \
      PROT_READ | PROT_WRITE,                                                                                   \
      MAP_ANONYMOUS | MAP_PRIVATE | mmap_fixed_flag,                                                            \
      -1, 0                                                                                                     \
    );                                                                                                          \
                                                                                                                \
    if (addr && addr != ((void*) -1) && addr != page_addr) {                                                    \
      if (mmap_fixed_flag == MAP_FIXED_NOREPLACE) {                                                             \
        printf("Warning: Mismatched HFI_EMULATION mode address: Got %p, Expected %p. Switching to MAP_FIXED\n", \
          addr, page_addr);                                                                                     \
        mmap_fixed_flag = MAP_FIXED;                                                                            \
        munmap(addr, alloc_size);                                                                               \
        addr = NULL;                                                                                            \
      } else {                                                                                                  \
        printf("Error: Mismatched HFI_EMULATION mode address: Got %p, Expected %p. \n",                         \
          addr, page_addr);                                                                                     \
        abort();                                                                                                \
      }                                                                                                         \
    }                                                                                                           \
                                                                                                                \
    if (addr && addr != ((void*) -1)) {                                                                         \
      break;                                                                                                    \
    }                                                                                                           \
  }                                                                                                             \
                                                                                                                \
  if (!addr || addr == ((void*) -1)) {                                                                          \
    printf("Reserving lower 4GB failed!!!!!!!!!\n");                                                            \
    abort();                                                                                                    \
  }                                                                                                             \
                                                                                                                \
  int allocated_correct = addr == page_addr;                                                                    \
  if(!allocated_correct) {                                                                                      \
    printf("Reserving lower 4GB was incorrect!!!!!!!!!\n");                                                     \
    abort();                                                                                                    \
  }                                                                                                             \
}
#endif

// One time init function for wasm runtime. Should be called once for the
// current process
extern void wasm_rt_sys_init();

// Initialize wasi for the given sandbox. Called prior to sandbox execution.
extern void wasm_rt_init_wasi(wasm_sandbox_wasi_data*);

extern void wasm_rt_cleanup_wasi(wasm_sandbox_wasi_data*);

// Helper function that host can use to ensure wasm2c code is loaded correctly
// when using dynamic libraries
extern void wasm2c_ensure_linked();

typedef struct wasm2c_configuration {
  uint8_t bit_WASM_USE_GUARD_PAGES;
  uint8_t bit_WASM_USE_BOUNDS_CHECKS;
  uint8_t bit_WASM_USE_HFI;
  uint8_t bit_WASM_USE_MASKING;
  uint8_t bit_WASM_NO_UVWASI;
  uint8_t bit_WASM_USE_MMAP;
  uint8_t bit_WASM_USE_MALLOC_IMMOVABLE;
  uint8_t bit_WASM_USE_MALLOC_MOVABLE;
  uint8_t bit_HFI_EMULATION_RR;
  uint8_t bit_HFI_EMULATION;
  uint8_t bit_HFI_EMULATION2;
  uint8_t bit_HFI_EMULATION3;
  uint8_t bit_WASM_CHECK_SHADOW_MEMORY;
} wasm2c_configuration;

#ifdef WASM_USE_GUARD_PAGES
#define VAL_WASM_USE_GUARD_PAGES 1
#else
#define VAL_WASM_USE_GUARD_PAGES 0
#endif

#ifdef WASM_USE_BOUNDS_CHECKS
#define VAL_WASM_USE_BOUNDS_CHECKS 1
#else
#define VAL_WASM_USE_BOUNDS_CHECKS 0
#endif

#ifdef WASM_USE_HFI
#define VAL_WASM_USE_HFI 1
#else
#define VAL_WASM_USE_HFI 0
#endif

#ifdef WASM_USE_MASKING
#define VAL_WASM_USE_MASKING 1
#else
#define VAL_WASM_USE_MASKING 0
#endif

#ifdef WASM_NO_UVWASI
#define VAL_WASM_NO_UVWASI 1
#else
#define VAL_WASM_NO_UVWASI 0
#endif

#ifdef WASM_USE_MMAP
#define VAL_WASM_USE_MMAP 1
#else
#define VAL_WASM_USE_MMAP 0
#endif

#ifdef WASM_USE_MALLOC_IMMOVABLE
#define VAL_WASM_USE_MALLOC_IMMOVABLE 1
#else
#define VAL_WASM_USE_MALLOC_IMMOVABLE 0
#endif

#ifdef WASM_USE_MALLOC_MOVABLE
#define VAL_WASM_USE_MALLOC_MOVABLE 1
#else
#define VAL_WASM_USE_MALLOC_MOVABLE 0
#endif

#ifdef HFI_EMULATION_RR
#define VAL_HFI_EMULATION_RR 1
#else
#define VAL_HFI_EMULATION_RR 0
#endif

#ifdef HFI_EMULATION
#define VAL_HFI_EMULATION 1
#else
#define VAL_HFI_EMULATION 0
#endif

#ifdef HFI_EMULATION2
#define VAL_HFI_EMULATION2 1
#else
#define VAL_HFI_EMULATION2 0
#endif

#ifdef HFI_EMULATION3
#define VAL_HFI_EMULATION3 1
#else
#define VAL_HFI_EMULATION3 0
#endif

#ifdef WASM_CHECK_SHADOW_MEMORY
#define VAL_WASM_CHECK_SHADOW_MEMORY 1
#else
#define VAL_WASM_CHECK_SHADOW_MEMORY 0
#endif

#define wasm2c_configuration_init() {   \
  VAL_WASM_USE_GUARD_PAGES,             \
  VAL_WASM_USE_BOUNDS_CHECKS,           \
  VAL_WASM_USE_HFI,                     \
  VAL_WASM_USE_MASKING,                 \
  VAL_WASM_NO_UVWASI,                   \
  VAL_WASM_USE_MMAP,                    \
  VAL_WASM_USE_MALLOC_IMMOVABLE,        \
  VAL_WASM_USE_MALLOC_MOVABLE,          \
  VAL_HFI_EMULATION_RR,                 \
  VAL_HFI_EMULATION,                    \
  VAL_HFI_EMULATION2,                   \
  VAL_HFI_EMULATION3,                   \
  VAL_WASM_CHECK_SHADOW_MEMORY          \
}

// Function to check configuration compatibility between binary and runtime
extern void wasm2c_configuration_check(wasm2c_configuration* code_config, size_t config_size);

extern void wasm2c_memory_check(wasm_rt_memory_t* mem);

// Runtime functions for shadow memory

// Create the shadow memory
extern void wasm2c_shadow_memory_create(wasm_rt_memory_t* mem);
// Expand the shadow memory to match wasm memory
extern void wasm2c_shadow_memory_expand(wasm_rt_memory_t* mem);
// Cleanup
extern void wasm2c_shadow_memory_destroy(wasm_rt_memory_t* mem);
// Perform checks for the load operation that completed
WASM2C_FUNC_EXPORT extern void wasm2c_shadow_memory_load(wasm_rt_memory_t* mem,
                                                         const char* func_name,
                                                         uint32_t ptr,
                                                         uint32_t ptr_size);
// Perform checks for the store operation that completed
WASM2C_FUNC_EXPORT extern void wasm2c_shadow_memory_store(wasm_rt_memory_t* mem,
                                                          const char* func_name,
                                                          uint32_t ptr,
                                                          uint32_t ptr_size);
// Mark an area as allocated, if it is currently unused. If already used, this
// is a noop.
extern void wasm2c_shadow_memory_reserve(wasm_rt_memory_t* mem,
                                         uint32_t ptr,
                                         uint32_t ptr_size);
// Perform checks for the malloc operation that completed
extern void wasm2c_shadow_memory_dlmalloc(wasm_rt_memory_t* mem,
                                          uint32_t ptr,
                                          uint32_t ptr_size);
// Perform checks for the free operation that will be run
extern void wasm2c_shadow_memory_dlfree(wasm_rt_memory_t* mem, uint32_t ptr);
// Pass on information about the boundary between wasm globals and heap
// Shadow asan will check that all malloc metadata structures below this
// boundary are only accessed by malloc related functions
extern void wasm2c_shadow_memory_mark_globals_heap_boundary(
    wasm_rt_memory_t* mem,
    uint32_t ptr);
// Print a list of all allocations currently active
WASM2C_FUNC_EXPORT extern void wasm2c_shadow_memory_print_allocations(
    wasm_rt_memory_t* mem);
// Print the size of allocations currently active
WASM2C_FUNC_EXPORT uint64_t
wasm2c_shadow_memory_print_total_allocations(wasm_rt_memory_t* mem);

extern void wasm2c_shadow_memory_closelog(wasm_rt_memory_t* mem);
extern void wasm2c_shadow_memory_logload(wasm_rt_memory_t* mem,
                                         const char* func_name,
                                         uint32_t ptr,
                                         uint32_t ptr_size,
                                         uint64_t data);
extern void wasm2c_shadow_memory_logstore(wasm_rt_memory_t* mem,
                                          const char* func_name,
                                          uint32_t ptr,
                                          uint32_t ptr_size,
                                          uint64_t data);


#ifdef __cplusplus
}
#endif

#endif /* WASM_RT_H_ */
