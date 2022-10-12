/* Generated from 'wasm2c.c.tmpl' by wasm2c_tmpl.py, do not edit! */
const char SECTION_NAME(includes)[] =
"/* Automically generated by wasm2c */\n"
"#include <math.h>\n"
"#include <string.h>\n"
"#include <stdlib.h>\n"
"\n"
"#ifndef WASM_NO_UVWASI\n"
"#include \"uvwasi.h\"\n"
"#endif\n"
"\n"
;

const char SECTION_NAME(declarations)[] =
"\n"
"#ifdef WASM_USE_HFI\n"
"#include \"hfi.h\"\n"
"#endif\n"
"\n"
"#if defined(_MSC_VER)\n"
"#  define UNLIKELY(x) (x)\n"
"#  define LIKELY(x) (x)\n"
"#else\n"
"#  define UNLIKELY(x) __builtin_expect(!!(x), 0)\n"
"#  define LIKELY(x) __builtin_expect(!!(x), 1)\n"
"#endif\n"
"\n"
"#define TRAP(x) (wasm_rt_trap(WASM_RT_TRAP_##x), 0)\n"
"\n"
"#ifndef FUNC_PROLOGUE\n"
"#define FUNC_PROLOGUE\n"
"#endif\n"
"\n"
"#ifndef FUNC_EPILOGUE\n"
"#define FUNC_EPILOGUE\n"
"#endif\n"
"\n"
"#ifdef EXTERNAL_CALLBACK_PROLOGUE\n"
"#define EXTERNAL_CALLBACK_PROLOGUE_EXEC(table, x)                        \\\n"
"  if (UNLIKELY(table.data[x].func_class == WASM_RT_EXTERNAL_FUNCTION)) { \\\n"
"    EXTERNAL_CALLBACK_PROLOGUE;                                          \\\n"
"  }\n"
"#else\n"
"#define EXTERNAL_CALLBACK_PROLOGUE_EXEC(table, x)\n"
"#endif\n"
"\n"
"#ifdef EXTERNAL_CALLBACK_EPILOGUE\n"
"#define EXTERNAL_CALLBACK_EPILOGUE_EXEC(table, x)                        \\\n"
"  if (UNLIKELY(table.data[x].func_class == WASM_RT_EXTERNAL_FUNCTION)) { \\\n"
"    EXTERNAL_CALLBACK_EPILOGUE;                                          \\\n"
"  }\n"
"#else\n"
"#define EXTERNAL_CALLBACK_EPILOGUE_EXEC(table, x)\n"
"#endif\n"
"\n"
"#define UNREACHABLE (void) TRAP(UNREACHABLE)\n"
"\n"
"#define CALL_INDIRECT_VOID(table, t, ft, x, func_types, ...)                                         \\\n"
"  if (LIKELY((x) < table.size && table.data[x].func && table.data[x].func_type == func_types[ft])) { \\\n"
"    EXTERNAL_CALLBACK_PROLOGUE_EXEC(table, x);                                                       \\\n"
"    ((t)table.data[x].func)(__VA_ARGS__);                                                            \\\n"
"    EXTERNAL_CALLBACK_EPILOGUE_EXEC(table, x);                                                       \\\n"
"  } else {                                                                                           \\\n"
"    wasm_rt_callback_error_trap(&table, x, func_types[ft]);                                          \\\n"
"  }\n"
"\n"
"#define CALL_INDIRECT_RES(res, table, t, ft, x, func_types, ...)                                     \\\n"
"  if (LIKELY((x) < table.size && table.data[x].func && table.data[x].func_type == func_types[ft])) { \\\n"
"    EXTERNAL_CALLBACK_PROLOGUE_EXEC(table, x);                                                       \\\n"
"    res = ((t)table.data[x].func)(__VA_ARGS__);                                                      \\\n"
"    EXTERNAL_CALLBACK_EPILOGUE_EXEC(table, x);                                                       \\\n"
"  } else {                                                                                           \\\n"
"    wasm_rt_callback_error_trap(&table, x, func_types[ft]);                                          \\\n"
"  }\n"
"\n"
"#if defined(WASM2C_MALLOC_FAIL_CALLBACK)\n"
"void WASM2C_MALLOC_FAIL_CALLBACK(u32 ptr_size);\n"
"# define WASM2C_MALLOC_FAIL_CHECK(ptr, ptr_size)  \\\n"
"  if (!ptr) {                                     \\\n"
"    WASM2C_MALLOC_FAIL_CALLBACK(ptr_size);        \\\n"
"  }\n"
"#else\n"
"# define WASM2C_MALLOC_FAIL_CHECK(ptr, ptr_size)\n"
"#endif\n"
"\n"
"#if defined(WASM_CHECK_SHADOW_MEMORY)\n"
"#  define WASM2C_SHADOW_MEMORY_LOAD(mem, func_name, ptr, ptr_size)  wasm2c_shadow_memory_load(mem, func_name, ptr, ptr_size)\n"
"#  define WASM2C_SHADOW_MEMORY_STORE(mem, func_name, ptr, ptr_size) wasm2c_shadow_memory_store(mem, func_name, ptr, ptr_size)\n"
"#  define WASM2C_SHADOW_MEMORY_RESERVE(mem, ptr, ptr_size)          wasm2c_shadow_memory_reserve(mem, ptr, ptr_size)\n"
"#  define WASM2C_SHADOW_MEMORY_DLMALLOC(mem, ptr, ptr_size)         wasm2c_shadow_memory_dlmalloc(mem, ptr, ptr_size)\n"
"#  define WASM2C_SHADOW_MEMORY_DLFREE(mem, ptr)                     wasm2c_shadow_memory_dlfree(mem, ptr)\n"
"#  define WASM2C_SHADOW_MEMORY_MARK_GLOBALS_HEAP_BOUNDARY(mem, ptr) wasm2c_shadow_memory_mark_globals_heap_boundary(mem, ptr)\n"
"#else\n"
"#  define WASM2C_SHADOW_MEMORY_LOAD(mem, func_name, ptr, ptr_size)\n"
"#  define WASM2C_SHADOW_MEMORY_STORE(mem, func_name, ptr, ptr_size)\n"
"#  define WASM2C_SHADOW_MEMORY_RESERVE(mem, ptr, ptr_size)\n"
"#  define WASM2C_SHADOW_MEMORY_DLMALLOC(mem, ptr, ptr_size)\n"
"#  define WASM2C_SHADOW_MEMORY_DLFREE(mem, ptr)\n"
"#  define WASM2C_SHADOW_MEMORY_MARK_GLOBALS_HEAP_BOUNDARY(mem, ptr)\n"
"#endif\n"
"\n"
"#ifdef WASM_USE_BOUNDS_CHECKS\n"
"#  define MEMCHECK(mem, a, t) if (UNLIKELY((a) + sizeof(t) > mem->size)) { (void) TRAP(OOB); }\n"
"#else\n"
"#  define MEMCHECK(mem, a, t)\n"
"#endif\n"
"\n"
"#ifdef WASM_USE_MASKING\n"
"#  define MEM_ACCESS_REF(mem, addr) &mem->data[addr & mem->mem_mask]\n"
"#elif defined(WASM_USE_HFI)\n"
"#  define MEM_ACCESS_REF(mem, addr) (char*) addr\n"
"#else\n"
"#  define MEM_ACCESS_REF(mem, addr) &mem->data[addr]\n"
"#endif\n"
"\n"
"\n"
"#if WABT_BIG_ENDIAN\n"
"\n"
"#error \"Unsupported\"\n"
"\n"
"#else\n"
"static inline void load_data(void *dest, const void *src, size_t n) {\n"
"  memcpy(dest, src, n);\n"
"}\n"
"\n"
"#ifdef HFI_EMULATION\n"
"#define LOAD_DATA(m, o, i, s) { load_data((void*)o, i, s); \\\n"
"  WASM2C_SHADOW_MEMORY_RESERVE(&m, o, s);                       \\\n"
"  WASM2C_SHADOW_MEMORY_STORE(&m, \"GlobalDataLoad\", o, s);       \\\n"
"}\n"
"#else\n"
"#define LOAD_DATA(m, o, i, s) { load_data(&(m.data[o]), i, s); \\\n"
"  WASM2C_SHADOW_MEMORY_RESERVE(&m, o, s);                       \\\n"
"  WASM2C_SHADOW_MEMORY_STORE(&m, \"GlobalDataLoad\", o, s);       \\\n"
"}\n"
"#endif\n"
"#define DEFINE_NONHFI_LOAD(name, act_t, signed_wasmrep_t, wasmrep_t)                     \\\n"
"  static inline wasmrep_t name(wasm_rt_memory_t* mem, u64 addr, const char* func_name) { \\\n"
"    MEMCHECK(mem, addr, act_t);                                                          \\\n"
"    act_t result;                                                                        \\\n"
"    memcpy(&result, MEM_ACCESS_REF(mem, addr), sizeof(act_t));                           \\\n"
"    WASM2C_SHADOW_MEMORY_LOAD(mem, func_name, addr, sizeof(act_t));                      \\\n"
"    return (wasmrep_t)(signed_wasmrep_t)result;                                          \\\n"
"  }\n"
"\n"
"#define DEFINE_NONHFI_STORE(name, act_t, wasmrep_t)                                                  \\\n"
"  static inline void name(wasm_rt_memory_t* mem, u64 addr, wasmrep_t value, const char* func_name) { \\\n"
"    MEMCHECK(mem, addr, act_t);                                                                      \\\n"
"    act_t wrapped = (act_t)value;                                                                    \\\n"
"    memcpy(MEM_ACCESS_REF(mem, addr), &wrapped, sizeof(act_t));                                      \\\n"
"    WASM2C_SHADOW_MEMORY_STORE(mem, func_name, addr, sizeof(act_t));                                 \\\n"
"  }\n"
"\n"
"#define DEFINE_HFI_LOAD(name, act_t, signed_wasmrep_t, wasmrep_t)                        \\\n"
"  static inline wasmrep_t name(wasm_rt_memory_t* mem, u64 addr, const char* func_name) { \\\n"
"    MEMCHECK(mem, addr, act_t);                                                          \\\n"
"    act_t out_result;                                                                    \\\n"
"    hfi_mov1_load_anytype(MEM_ACCESS_REF(mem, addr), out_result);                        \\\n"
"    WASM2C_SHADOW_MEMORY_LOAD(mem, func_name, addr, sizeof(act_t));                      \\\n"
"    return (wasmrep_t)(signed_wasmrep_t)out_result;                                      \\\n"
"  }\n"
"\n"
"#define DEFINE_HFI_STORE(name, act_t, wasmrep_t)                                                     \\\n"
"  static inline void name(wasm_rt_memory_t* mem, u64 addr, wasmrep_t value, const char* func_name) { \\\n"
"    MEMCHECK(mem, addr, act_t);                                                                      \\\n"
"    act_t wrapped = (act_t)value;                                                                    \\\n"
"    hfi_mov1_store_anytype(MEM_ACCESS_REF(mem, addr), wrapped);                                      \\\n"
"    WASM2C_SHADOW_MEMORY_STORE(mem, func_name, addr, sizeof(act_t));                                 \\\n"
"  }\n"
"#endif\n"
"\n"
"#ifdef WASM_USE_HFI\n"
"\n"
"#define DEFINE_LOAD DEFINE_HFI_LOAD\n"
"#define DEFINE_STORE DEFINE_HFI_STORE\n"
"\n"
"#else\n"
"\n"
"#define DEFINE_LOAD DEFINE_NONHFI_LOAD\n"
"#define DEFINE_STORE DEFINE_NONHFI_STORE\n"
"\n"
"#endif\n"
"\n"
"DEFINE_LOAD(i32_load, u32, u32, u32);\n"
"DEFINE_LOAD(i64_load, u64, u64, u64);\n"
"DEFINE_LOAD(f32_load, f32, f32, f32);\n"
"DEFINE_LOAD(f64_load, f64, f64, f64);\n"
"DEFINE_LOAD(i32_load8_s, s8, s32, u32);\n"
"DEFINE_LOAD(i64_load8_s, s8, s64, u64);\n"
"DEFINE_LOAD(i32_load8_u, u8, u32, u32);\n"
"DEFINE_LOAD(i64_load8_u, u8, u64, u64);\n"
"DEFINE_LOAD(i32_load16_s, s16, s32, u32);\n"
"DEFINE_LOAD(i64_load16_s, s16, s64, u64);\n"
"DEFINE_LOAD(i32_load16_u, u16, u32, u32);\n"
"DEFINE_LOAD(i64_load16_u, u16, u64, u64);\n"
"DEFINE_LOAD(i64_load32_s, s32, s64, u64);\n"
"DEFINE_LOAD(i64_load32_u, u32, u64, u64);\n"
"DEFINE_STORE(i32_store, u32, u32);\n"
"DEFINE_STORE(i64_store, u64, u64);\n"
"DEFINE_STORE(f32_store, f32, f32);\n"
"DEFINE_STORE(f64_store, f64, f64);\n"
"DEFINE_STORE(i32_store8, u8, u32);\n"
"DEFINE_STORE(i32_store16, u16, u32);\n"
"DEFINE_STORE(i64_store8, u8, u64);\n"
"DEFINE_STORE(i64_store16, u16, u64);\n"
"DEFINE_STORE(i64_store32, u32, u64);\n"
"\n"
"#if defined(_MSC_VER)\n"
"#include <intrin.h>\n"
"\n"
"// Adapted from https://github.com/nemequ/portable-snippets/blob/master/builtin/builtin.h\n"
"\n"
"static inline int I64_CLZ(unsigned long long v) {\n"
"  unsigned long r = 0;\n"
"#if defined(_M_AMD64) || defined(_M_ARM)\n"
"    if (_BitScanReverse64(&r, v)) {\n"
"      return 63 - r;\n"
"    }\n"
"#else\n"
"    if (_BitScanReverse(&r, (unsigned long) (v >> 32))) {\n"
"      return 31 - r;\n"
"    } else if (_BitScanReverse(&r, (unsigned long) v)) {\n"
"      return 63 - r;\n"
"    }\n"
"#endif\n"
"  return 64;\n"
"}\n"
"\n"
"static inline int I32_CLZ(unsigned long v) {\n"
"  unsigned long r = 0;\n"
"  if (_BitScanReverse(&r, v)) {\n"
"    return 31 - r;\n"
"  }\n"
"  return 32;\n"
"}\n"
"\n"
"static inline int I64_CTZ(unsigned long long v) {\n"
"  if (!v) {\n"
"    return 64;\n"
"  }\n"
"  unsigned long r = 0;\n"
"#if defined(_M_AMD64) || defined(_M_ARM)\n"
"    _BitScanForward64(&r, v);\n"
"    return (int) r;\n"
"#else\n"
"    if (_BitScanForward(&r, (unsigned int) (v))) {\n"
"      return (int) (r);\n"
"    }\n"
"\n"
"    _BitScanForward(&r, (unsigned int) (v >> 32));\n"
"    return (int) (r + 32);\n"
"#endif\n"
"}\n"
"\n"
"static inline int I32_CTZ(unsigned long v) {\n"
"  if (!v) {\n"
"    return 32;\n"
"  }\n"
"  unsigned long r = 0;\n"
"  _BitScanForward(&r, v);\n"
"  return (int) r;\n"
"}\n"
"\n"
"#define POPCOUNT_DEFINE_PORTABLE(f_n, T)                    \\\n"
"  static inline u32 f_n(T x) {                              \\\n"
"    x = x - ((x >> 1) & (T)~(T)0/3);                        \\\n"
"    x = (x & (T)~(T)0/15*3) + ((x >> 2) & (T)~(T)0/15*3);   \\\n"
"    x = (x + (x >> 4)) & (T)~(T)0/255*15;                   \\\n"
"    return (T)(x * ((T)~(T)0/255)) >> (sizeof(T) - 1) * 8;  \\\n"
"  }\n"
"\n"
"POPCOUNT_DEFINE_PORTABLE(I32_POPCNT, u32)\n"
"POPCOUNT_DEFINE_PORTABLE(I64_POPCNT, u64)\n"
"\n"
"#undef POPCOUNT_DEFINE_PORTABLE\n"
"\n"
"#else\n"
"#  define I32_CLZ(x) ((x) ? __builtin_clz(x) : 32)\n"
"#  define I64_CLZ(x) ((x) ? __builtin_clzll(x) : 64)\n"
"#  define I32_CTZ(x) ((x) ? __builtin_ctz(x) : 32)\n"
"#  define I64_CTZ(x) ((x) ? __builtin_ctzll(x) : 64)\n"
"#  define I32_POPCNT(x) (__builtin_popcount(x))\n"
"#  define I64_POPCNT(x) (__builtin_popcountll(x))\n"
"#endif\n"
"\n"
"#define DIV_S(ut, min, x, y)                                 \\\n"
"   ((UNLIKELY((y) == 0)) ?                TRAP(DIV_BY_ZERO)  \\\n"
"  : (UNLIKELY((x) == min && (y) == -1)) ? TRAP(INT_OVERFLOW) \\\n"
"  : (ut)((x) / (y)))\n"
"\n"
"#define REM_S(ut, min, x, y)                                \\\n"
"   ((UNLIKELY((y) == 0)) ?                TRAP(DIV_BY_ZERO) \\\n"
"  : (UNLIKELY((x) == min && (y) == -1)) ? 0                 \\\n"
"  : (ut)((x) % (y)))\n"
"\n"
"#define I32_DIV_S(x, y) DIV_S(u32, INT32_MIN, (s32)x, (s32)y)\n"
"#define I64_DIV_S(x, y) DIV_S(u64, INT64_MIN, (s64)x, (s64)y)\n"
"#define I32_REM_S(x, y) REM_S(u32, INT32_MIN, (s32)x, (s32)y)\n"
"#define I64_REM_S(x, y) REM_S(u64, INT64_MIN, (s64)x, (s64)y)\n"
"\n"
"#define DIVREM_U(op, x, y) \\\n"
"  ((UNLIKELY((y) == 0)) ? TRAP(DIV_BY_ZERO) : ((x) op (y)))\n"
"\n"
"#define DIV_U(x, y) DIVREM_U(/, x, y)\n"
"#define REM_U(x, y) DIVREM_U(%, x, y)\n"
"\n"
"#define ROTL(x, y, mask) \\\n"
"  (((x) << ((y) & (mask))) | ((x) >> (((mask) - (y) + 1) & (mask))))\n"
"#define ROTR(x, y, mask) \\\n"
"  (((x) >> ((y) & (mask))) | ((x) << (((mask) - (y) + 1) & (mask))))\n"
"\n"
"#define I32_ROTL(x, y) ROTL(x, y, 31)\n"
"#define I64_ROTL(x, y) ROTL(x, y, 63)\n"
"#define I32_ROTR(x, y) ROTR(x, y, 31)\n"
"#define I64_ROTR(x, y) ROTR(x, y, 63)\n"
"\n"
"#define FMIN(x, y)                                          \\\n"
"   ((UNLIKELY((x) != (x))) ? NAN                            \\\n"
"  : (UNLIKELY((y) != (y))) ? NAN                            \\\n"
"  : (UNLIKELY((x) == 0 && (y) == 0)) ? (signbit(x) ? x : y) \\\n"
"  : (x < y) ? x : y)\n"
"\n"
"#define FMAX(x, y)                                          \\\n"
"   ((UNLIKELY((x) != (x))) ? NAN                            \\\n"
"  : (UNLIKELY((y) != (y))) ? NAN                            \\\n"
"  : (UNLIKELY((x) == 0 && (y) == 0)) ? (signbit(x) ? y : x) \\\n"
"  : (x > y) ? x : y)\n"
"\n"
"#define TRUNC_S(ut, st, ft, min, minop, max, x)                             \\\n"
"  ((UNLIKELY((x) != (x)))                        ? TRAP(INVALID_CONVERSION) \\\n"
"   : (UNLIKELY(!((x)minop(min) && (x) < (max)))) ? TRAP(INT_OVERFLOW)       \\\n"
"                                                 : (ut)(st)(x))\n"
"\n"
"#define I32_TRUNC_S_F32(x) TRUNC_S(u32, s32, f32, (f32)INT32_MIN, >=, 2147483648.f, x)\n"
"#define I64_TRUNC_S_F32(x) TRUNC_S(u64, s64, f32, (f32)INT64_MIN, >=, (f32)INT64_MAX, x)\n"
"#define I32_TRUNC_S_F64(x) TRUNC_S(u32, s32, f64, -2147483649., >, 2147483648., x)\n"
"#define I64_TRUNC_S_F64(x) TRUNC_S(u64, s64, f64, (f64)INT64_MIN, >=, (f64)INT64_MAX, x)\n"
"\n"
"#define TRUNC_U(ut, ft, max, x)                                            \\\n"
"  ((UNLIKELY((x) != (x)))                       ? TRAP(INVALID_CONVERSION) \\\n"
"   : (UNLIKELY(!((x) > (ft)-1 && (x) < (max)))) ? TRAP(INT_OVERFLOW)       \\\n"
"                                                : (ut)(x))\n"
"\n"
"#define I32_TRUNC_U_F32(x) TRUNC_U(u32, f32, 4294967296.f, x)\n"
"#define I64_TRUNC_U_F32(x) TRUNC_U(u64, f32, (f32)UINT64_MAX, x)\n"
"#define I32_TRUNC_U_F64(x) TRUNC_U(u32, f64, 4294967296.,  x)\n"
"#define I64_TRUNC_U_F64(x) TRUNC_U(u64, f64, (f64)UINT64_MAX, x)\n"
"\n"
"#define TRUNC_SAT_S(ut, st, ft, min, smin, minop, max, smax, x) \\\n"
"  ((UNLIKELY((x) != (x)))         ? 0                           \\\n"
"   : (UNLIKELY(!((x)minop(min)))) ? smin                        \\\n"
"   : (UNLIKELY(!((x) < (max))))   ? smax                        \\\n"
"                                  : (ut)(st)(x))\n"
"\n"
"#define I32_TRUNC_SAT_S_F32(x) TRUNC_SAT_S(u32, s32, f32, (f32)INT32_MIN, INT32_MIN, >=, 2147483648.f, INT32_MAX, x)\n"
"#define I64_TRUNC_SAT_S_F32(x) TRUNC_SAT_S(u64, s64, f32, (f32)INT64_MIN, INT64_MIN, >=, (f32)INT64_MAX, INT64_MAX, x)\n"
"#define I32_TRUNC_SAT_S_F64(x) TRUNC_SAT_S(u32, s32, f64, -2147483649., INT32_MIN, >, 2147483648., INT32_MAX, x)\n"
"#define I64_TRUNC_SAT_S_F64(x) TRUNC_SAT_S(u64, s64, f64, (f64)INT64_MIN, INT64_MIN, >=, (f64)INT64_MAX, INT64_MAX, x)\n"
"\n"
"#define TRUNC_SAT_U(ut, ft, max, smax, x) \\\n"
"  ((UNLIKELY((x) != (x)))        ? 0      \\\n"
"   : (UNLIKELY(!((x) > (ft)-1))) ? 0      \\\n"
"   : (UNLIKELY(!((x) < (max))))  ? smax   \\\n"
"                                 : (ut)(x))\n"
"\n"
"#define I32_TRUNC_SAT_U_F32(x) TRUNC_SAT_U(u32, f32, 4294967296.f, UINT32_MAX, x)\n"
"#define I64_TRUNC_SAT_U_F32(x) TRUNC_SAT_U(u64, f32, (f32)UINT64_MAX, UINT64_MAX, x)\n"
"#define I32_TRUNC_SAT_U_F64(x) TRUNC_SAT_U(u32, f64, 4294967296., UINT32_MAX,  x)\n"
"#define I64_TRUNC_SAT_U_F64(x) TRUNC_SAT_U(u64, f64, (f64)UINT64_MAX, UINT64_MAX, x)\n"
"\n"
"#define DEFINE_REINTERPRET(name, t1, t2)  \\\n"
"  static inline t2 name(t1 x) {           \\\n"
"    t2 result;                            \\\n"
"    memcpy(&result, &x, sizeof(result));  \\\n"
"    return result;                        \\\n"
"  }\n"
"\n"
"DEFINE_REINTERPRET(f32_reinterpret_i32, u32, f32)\n"
"DEFINE_REINTERPRET(i32_reinterpret_f32, f32, u32)\n"
"DEFINE_REINTERPRET(f64_reinterpret_i64, u64, f64)\n"
"DEFINE_REINTERPRET(i64_reinterpret_f64, f64, u64)\n"
;

const char SECTION_NAME(sandboxapis)[] =
"//test\n"
"\n"
"static u32 add_wasm2c_callback(void* sbx_ptr, u32 func_type_idx, void* func_ptr, wasm_rt_elem_target_class_t func_class) {\n"
"  wasm_rt_table_t* table = get_wasm2c_callback_table(sbx_ptr);\n"
"  for (u32 i = 1; i < table->max_size; i++) {\n"
"    if (i >= table->size) {\n"
"      wasm_rt_expand_table(table);\n"
"    }\n"
"    if (table->data[i].func == 0) {\n"
"      table->data[i] = (wasm_rt_elem_t){ func_class, func_type_idx, (wasm_rt_anyfunc_t) func_ptr };\n"
"      return i;\n"
"    }\n"
"  }\n"
"  (void) TRAP(CALL_INDIRECT_TABLE_EXPANSION);\n"
"}\n"
"\n"
"static void remove_wasm2c_callback(void* sbx_ptr, u32 callback_idx) {\n"
"  wasm_rt_table_t* table = get_wasm2c_callback_table(sbx_ptr);\n"
"  table->data[callback_idx].func = 0;\n"
"}\n"
"\n"
"static u32 lookup_wasm2c_func_index(void* sbx_ptr, u32 param_count, u32 result_count, wasm_rt_type_t* types) {\n"
"  wasm2c_sandbox_t* const sbx = (wasm2c_sandbox_t* const) sbx_ptr;\n"
"  return wasm_rt_register_func_type(&sbx->func_type_structs, &sbx->func_type_count, param_count, result_count, types);\n"
"}\n"
"\n"
"static void* create_wasm2c_sandbox(uint32_t max_wasm_pages) {\n"
"  wasm2c_configuration code_config = wasm2c_configuration_init();\n"
"  wasm2c_configuration_check(&code_config, sizeof(code_config));\n"
"  wasm2c_sandbox_t* const sbx = (wasm2c_sandbox_t* const) calloc(sizeof(wasm2c_sandbox_t), 1);\n"
"  if (!init_memory(sbx, max_wasm_pages)) {\n"
"    free(sbx);\n"
"    return 0;\n"
"  }\n"
"  init_func_types(sbx);\n"
"  init_globals(sbx);\n"
"  init_table(sbx);\n"
"  wasm_rt_init_wasi(&(sbx->wasi_data));\n"
"  init_module_starts();\n"
"  return sbx;\n"
"}\n"
"\n"
"static void destroy_wasm2c_sandbox(void* aSbx) {\n"
"  wasm2c_sandbox_t* const sbx = (wasm2c_sandbox_t* const) aSbx;\n"
"  cleanup_memory(sbx);\n"
"  cleanup_func_types(sbx);\n"
"  cleanup_table(sbx);\n"
"  wasm_rt_cleanup_wasi(&(sbx->wasi_data));\n"
"  free(sbx);\n"
"}\n"
"\n"
"#ifndef WASM_NO_UVWASI\n"
"static void init_uvwasi_state(void* aSbx, uvwasi_t * uvwasi_p) {\n"
"  wasm2c_sandbox_t* const sbx = (wasm2c_sandbox_t* const) aSbx;\n"
"  sbx->wasi_data.uvwasi = uvwasi_p;\n"
"}\n"
"#endif\n"
"\n"
"FUNC_EXPORT wasm2c_sandbox_funcs_t WASM_CURR_ADD_PREFIX(get_wasm2c_sandbox_info)() {\n"
"  wasm2c_sandbox_funcs_t ret;\n"
"  ret.wasm_rt_sys_init = &wasm_rt_sys_init;\n"
"  ret.create_wasm2c_sandbox = &create_wasm2c_sandbox;\n"
"  ret.destroy_wasm2c_sandbox = &destroy_wasm2c_sandbox;\n"
"#ifndef WASM_NO_UVWASI\n"
"  ret.init_uvwasi_state = &init_uvwasi_state;\n"
"#endif\n"
"  ret.lookup_wasm2c_nonfunc_export = &lookup_wasm2c_nonfunc_export;\n"
"  ret.lookup_wasm2c_func_index = &lookup_wasm2c_func_index;\n"
"  ret.add_wasm2c_callback = &add_wasm2c_callback;\n"
"  ret.remove_wasm2c_callback = &remove_wasm2c_callback;\n"
"  ret.get_wasm2c_memory = &get_wasm2c_memory;\n"
"  return ret;\n"
"}\n"
;
