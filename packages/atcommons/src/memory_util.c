#include "atlogger/atlogger.h"
#include <atcommons/memory_util.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define TAG "atcommons_memlist"
struct atcommons_memlist atcommons_memlist_create(uint32_t len) {
  // the only way to check this at compile time is the road to macro hell
  // while it would make more robust code when done right, it would be a waste
  // of time trying to get it right (at least right now)
  if (len > ATCOMMONS_MEMLIST_SIZE) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "requested length exceeds the maximum allowed: %d; allocating maximum of %d instead\n", len,
                 ATCOMMONS_MEMLIST_SIZE);
    len = ATCOMMONS_MEMLIST_SIZE;
  }
  return (struct atcommons_memlist){
      .len = len,
      .free_on_success = 0,
      .allocated = 0,
      .memory = {(struct atcommons_memory_deallocator){.memory = NULL, .free_fn = NULL}},
  };
}

int atcommons_memlist_add(struct atcommons_memlist *memlist, void *memory, bool free_on_success, void *free_fn) {
  if (memory == NULL && free_fn == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "One of memory and free_fn must be non-NULL\n");
    return 1;
  }
  uint32_t index = ATCOMMONS_MEMLIST_SIZE; // intentionally out of bounds by default
  for (uint32_t i = 0; i < memlist->len && i < ATCOMMONS_MEMLIST_SIZE; i++) {
    if ((memlist->allocated & (0b1 << i)) == 0) {
      index = i;
      break;
    }
  }
  if (index == ATCOMMONS_MEMLIST_SIZE) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "No more available space in memlist\n");
    return 2;
  }

  memlist->memory[index] = (struct atcommons_memory_deallocator){
      .memory = memory,
      .free_fn = free_fn,
  };
  memlist->allocated |= (0b1 << index); // set bit at index to 1

  if (free_on_success) {
    memlist->free_on_success |= (0b1 << index); // set bit at index to 1
  } else {
    memlist->free_on_success &= ~(0b1 << index); // set bit at index to 0
  }
  return 0;
}

int atcommons_memlist_index_free(struct atcommons_memlist *memlist, uint32_t index) {
  if (index > ATCOMMONS_MEMLIST_SIZE || index > memlist->len) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "requested index is invalid\n");
    return 1;
  }
  if ((memlist->allocated & (0b1 << index)) == 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "requested index is not allocated\n");
    return 2;
  }

  struct atcommons_memory_deallocator *dealloc = &memlist->memory[index];
  if (dealloc->memory == NULL && dealloc->free_fn == NULL) {
    atlogger_log(
        TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
        "Both memory address and free function are NULL, nothing has been provided to deallocate the memory\n");
    return 3;
  }

  // If there's a free function use that to free the memory
  // It is up to the consumer to call free on the actual memory address if that
  // is also required with any other cleanup logic
  if (dealloc->free_fn != NULL) {
    dealloc->free_fn(dealloc->memory);
  } else {
    free(dealloc->memory);
  }

  dealloc->free_fn = NULL;
  dealloc->memory = NULL;
  memlist->allocated &= ~(0b1 << index); // set bit at index to 0
  return 0;
}

void atcommons_memlist_failure_free(struct atcommons_memlist *memlist) {
  for (uint32_t i = 0; i < memlist->len; i++) {
    if ((memlist->allocated & (0b1 << i)) != 0) {
      atcommons_memlist_index_free(memlist, i);
    }
  }
}

void atcommons_memlist_success_free(struct atcommons_memlist *memlist) {
  // create a mask of bits where memory is allocated and free_on_success is true
  ATCOMMONS_MEMLIST_BITMASK_TYPE bitmask = memlist->allocated & memlist->free_on_success;
  for (uint32_t i = 0; i < memlist->len; i++) {
    if ((bitmask & (0b1 << i)) != 0) {
      atcommons_memlist_index_free(memlist, i);
    }
  }
}
