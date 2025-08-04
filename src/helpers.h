/* SPDX-License-Identifier: BSD-3-Clause */

#pragma once

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>

#define DIE(assertion, call_description)                                                                               \
	do {                                                                                                               \
		if (assertion) {                                                                                               \
			fprintf(stderr, "(%s, %d): ", __FILE__, __LINE__);                                                         \
			perror(call_description);                                                                                  \
			exit(errno);                                                                                               \
		}                                                                                                              \
	} while (0)

/* Structure to hold memory block metadata */
struct block_meta {
	size_t size;
	int status;
	struct block_meta *next;
}block_meta;

int calloc_called = 0;
int heap_preallocated = 0;
void *mem_list_head = NULL;

#define MMAP_THRESHOLD (128 * 1024)
#define MIN_BLOCK_SIZE (sizeof(struct block_meta) + 8)

/* Block metadata status values */
#define STATUS_FREE   0
#define STATUS_ALLOC  1
#define STATUS_MAPPED 2



// Returneaza metadatele asociate lui ptr
struct block_meta *get_block_ptr(void *ptr) {
  return (struct block_meta*)ptr - 1;
}

struct block_meta* get_prev_block_ptr(struct block_meta* block) {
    struct block_meta* current_block = mem_list_head, *prev_block = NULL;
    while (current_block && current_block != block) {
        prev_block = current_block;
        current_block = current_block->next;
    }
    if (current_block == block) {
        return prev_block;
    }
    return NULL;
}

/*
	Cauta un bloc FREE care sa satisfaca dimensiunile cerute
*/ 
struct block_meta *find_free_block(struct block_meta **mem_list_tail, size_t size) {
	struct block_meta *current = mem_list_head;
  	while (current && !(current->status == STATUS_FREE && current->size >= size)) {
    	*mem_list_tail = current;
    	current = current->next;
  	}
  	return current;
}
/*
	Aloca efectiv memorie cu sbrk() sau mmap(), in cazul in care
	find_free_block(...) esueaza
*/
struct block_meta *allocate_memory(struct block_meta* mem_list_tail, size_t size) {
    struct block_meta *block;
    void *payload;
    intptr_t request;

	if(calloc_called) { // Functia a fost apelata de os_calloc()
		size_t page_size = getpagesize();
		if (size + sizeof(struct block_meta) < page_size) { // Alocare cu sbrk()
			request = (intptr_t)sbrk(0);
			DIE(request == -1, "sbrk");

			size_t new_size;
			if (!heap_preallocated) {
				new_size = MMAP_THRESHOLD;
				heap_preallocated = 1;
			} else {
				// Aliniere dimensiune
				new_size = size + sizeof(struct block_meta) + (8 - (size + sizeof(struct block_meta)) % 8) % 8;
			}
			request = (intptr_t)sbrk(new_size);
			DIE(request == -1, "sbrk");

			block = (struct block_meta*)request;
			block->status = STATUS_ALLOC;
			// Aliniere payload
			payload = (void*) (((uintptr_t) (block + 1) + 7) & ~7);

		} else { // Alocare cu mmap()
			size_t total_size = size + sizeof(struct block_meta);
			size_t padding = (8 - (total_size % 8)) % 8;
			total_size += padding;

			request = (intptr_t) mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			DIE(request == -1, "mmap");

			block = (struct block_meta*)request;
			block->status = STATUS_MAPPED;
			// Aliniere payload
			payload = (void*) (((uintptr_t) (block + 1) + 7) & ~7);
			
		}
	} else { // Functia a fost apelata de os_malloc()
		if (size + sizeof(struct block_meta) < MMAP_THRESHOLD) {
			request = (intptr_t)sbrk(0);
			DIE(request == -1, "sbrk");

			size_t new_size;
			if (!heap_preallocated) {
				new_size = MMAP_THRESHOLD;
				heap_preallocated = 1;
			} else {
				// Aliniere dimensiune
				new_size = size + sizeof(block_meta) + (8 - (size + sizeof(struct block_meta)) % 8) % 8;
			}
			request = (intptr_t)sbrk(new_size);
			DIE(request == -1, "sbrk");

			block = (struct block_meta*)request;
			block->status = STATUS_ALLOC;
			// Aliniere payload
			payload = (void*) (((uintptr_t) (block + 1) + 7) & ~7);

		} else { // Alocare cu mmap()
			size_t total_size = size + sizeof(struct block_meta);
			size_t padding = (8 - (total_size % 8)) % 8;
			total_size += padding;

			request = (intptr_t) mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			DIE(request == -1, "mmap");

			block = (struct block_meta*)request;
			block->status = STATUS_MAPPED;
			// Aliniere payload
			payload = (void*) (((uintptr_t) (block + 1) + 7) & ~7);
		}
	}

	// La primul apel al functiei, mem_list_tail este NULL
    if (mem_list_tail) {
        mem_list_tail->next = block;
    }
    block->size = size;
    block->next = NULL;

    return (struct block_meta*) payload - 1;
}
