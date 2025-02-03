#ifndef ATCOMMONS_MEMORY_UTIL_H
#define ATCOMMONS_MEMORY_UTIL_H
#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

// change the following fields to change the maximum size
// ideally this stays 32 or 64 to align well on 32bit & 64bit systems
#define ATCOMMONS_MEMLIST_SIZE 32
#define ATCOMMONS_MEMLIST_BITMASK_TYPE uint32_t
#define ATCOMMONS_MEMLIST_BITMASK_TYPE_MAX UINT32_MAX

struct atcommons_memory_deallocator {
  void *memory;            // address of the memory to free
  void (*free_fn)(void *); // free function
};

// This could be optimized, but it's good enough for now, stability first
struct atcommons_memlist {
  struct atcommons_memory_deallocator memory[ATCOMMONS_MEMLIST_SIZE];
  ATCOMMONS_MEMLIST_BITMASK_TYPE free_on_success; // bitmask
  ATCOMMONS_MEMLIST_BITMASK_TYPE allocated;       // bitmask
  uint32_t len;                                   // length of the list
};

struct atcommons_memlist atcommons_memlist_create(uint32_t len);
int atcommons_memlist_add(struct atcommons_memlist *memlist, void *memory, bool free_on_success, void *free_fn);
int atcommons_memlist_index_free(struct atcommons_memlist *memlist, uint32_t index);
void atcommons_memlist_failure_free(struct atcommons_memlist *memlist);
void atcommons_memlist_success_free(struct atcommons_memlist *memlist);

#ifdef __cplusplus
}
#endif
#endif
