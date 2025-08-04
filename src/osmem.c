// SPDX-License-Identifier: BSD-3-Clause

#include "osmem.h"
#include "helpers.h"


void *os_malloc(size_t size)
{
	struct block_meta *block;

	if (size <= 0)
		return NULL;

	if (!mem_list_head) { // Primul apel al functiei
		block = allocate_memory(NULL, size);
		if (!block)
			return NULL;
		mem_list_head = block;
	} else {
		struct block_meta *mem_list_tail = mem_list_head;

		block = find_free_block(&mem_list_tail, size);
		if (!block) { // Nu s-a gasit un bloc FREE -> alocam memorie
			block = allocate_memory(mem_list_tail, size);
			if (!block)
				return NULL;
		} else { // S-a gasit un bloc FREE
			size_t new_size = block->size - size;

			if (new_size >= MIN_BLOCK_SIZE) {
				// Se poate face split pe bloc
				struct block_meta *new_block = (struct block_meta *)(((uintptr_t)(block + 1) + size + 7) & ~7);

				new_block->size = new_size - sizeof(struct block_meta);
				new_block->next = block->next;
				new_block->status = STATUS_FREE;
				block->next = new_block;
				block->size = size;
			}
			// Nu s-a putut face split => doar marcam blocul ca fiind alocat
			block->status = STATUS_ALLOC;
		}
	}

	// Returnam payload-ul, nu si metadatele
	return (block + 1);
}

void os_free(void *ptr)
{
	if (!ptr)
		return;

	struct block_meta *block_ptr = get_block_ptr(ptr);

	if (block_ptr->status == STATUS_MAPPED) {
		if (block_ptr == mem_list_head)
			mem_list_head = NULL;

		size_t total_size = block_ptr->size + sizeof(block_meta);
		size_t padding = (8 - (total_size % 8)) % 8;

		total_size += padding;

		int ret = munmap(block_ptr, total_size);

		DIE(ret == -1, "munmap");

	} else {
		// Nu returnam efectiv memoria catre SO, ci doar
		// marcam blocul ca fiind free
		block_ptr->status = STATUS_FREE;

		// Facem merge cu blocul din dreapta, daca este FREE
		struct block_meta *next_block_ptr = block_ptr->next;

		if (next_block_ptr && next_block_ptr->status == STATUS_FREE) {
			block_ptr->size += sizeof(struct block_meta) + next_block_ptr->size;
			block_ptr->next = next_block_ptr->next;
		}

		// Facem merge cu blocul din stanga, daca este FREE
		struct block_meta *prev_block_ptr = get_prev_block_ptr(block_ptr);

		if (prev_block_ptr && prev_block_ptr->status == STATUS_FREE) {
			prev_block_ptr->size += sizeof(struct block_meta) + block_ptr->size;
			prev_block_ptr->next = block_ptr->next;
		}
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	if (nmemb == 0 || size == 0)
		return NULL;

	calloc_called = 1;
	size_t new_size = nmemb * size;
	void *ptr = os_malloc(new_size);

	calloc_called = 0;

	memset(ptr, 0, new_size);
	return ptr;
}

void *os_realloc(void *ptr, size_t size)
{
	if (!ptr)
		return os_malloc(size);
	if (size == 0) {
		os_free(ptr);
		return NULL;
	}
	struct block_meta *block_ptr = get_block_ptr(ptr);

	if (block_ptr && block_ptr->status == STATUS_FREE)
		return NULL;

	if (!heap_preallocated) {
		intptr_t request = (intptr_t)sbrk(0);

		DIE(request == -1, "sbrk");

		request = (intptr_t)sbrk(MMAP_THRESHOLD);
		DIE(request == -1, "sbrk");

		struct block_meta *block = (struct block_meta *)request;

		block->status = STATUS_ALLOC;
		// Aliniere payload
		void *payload = (void *) (((uintptr_t) (block + 1) + 7) & ~7);

		block->size = size;
		block->next = NULL;

		heap_preallocated = 1;
		memcpy(payload, ptr, size);
		os_free(ptr);

		return (struct block_meta *)payload;
	}

	size_t old_size = block_ptr->size;

	if (old_size >= size) {
		size_t new_size = old_size - size;

		if (new_size >= MIN_BLOCK_SIZE) {
			// Se poate face split pe bloc
			struct block_meta *new_block = (struct block_meta *)(((uintptr_t)ptr + size + 7) & ~7);

			new_block->size = new_size - sizeof(struct block_meta);
			new_block->next = block_ptr->next;
			new_block->status = STATUS_FREE;
			block_ptr->next = new_block;
			block_ptr->size = size;
		}
		// Nu putem crea un nou bloc FREE => Doar returnam payload-ul
		return ptr;
	}
	// Facem merge blocurilor FREE
	struct block_meta *next_block_ptr = block_ptr->next;

	while (next_block_ptr && next_block_ptr->status == STATUS_FREE) {
		size_t new_size = block_ptr->size + sizeof(struct block_meta) + next_block_ptr->size;

		if (new_size >= size) {
			block_ptr->next = next_block_ptr->next;
			block_ptr->size = new_size;
			return ptr;
		}
		next_block_ptr = next_block_ptr->next;
	}

	// Blocul este realocat si se copiaza payload-ul
	void *new_ptr = os_malloc(size);

	if (!new_ptr)
		return NULL;
	memcpy(new_ptr, ptr, old_size);
	os_free(ptr);
	return new_ptr;
}
