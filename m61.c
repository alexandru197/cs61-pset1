#define M61_DISABLE 1
#define _GNU_SOURCE
#include "m61.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <assert.h>

// magic number used for buffer overflow protection
#define ENDMARKER "0xDEADBEEF"

// struct to store malloc metadata
struct header {
    size_t sz;              // size of the allocated block in bytes
    void *payload;          // pointer to the payload
    struct header *next;    // pointer to the next metadata struct
    struct header *prev;    // pointer to previous metadata struct
    const char *file;       // file where block was allocated
    int line;               // line where block was allocated
} header;

// struct for storing data for a single line for heavy hitters
struct heavy_hitter {
    size_t sz;
    int allocations;
    int line;
    const char *file;
} heavy_hitter;

// initialize an m61_statistics block track stats
struct m61_statistics statistics;

// pointer to the beginning of the metadata linked list, allocated later
struct header *metadata_list = NULL;

// pointer to the first element of heavy hitters, allocated later
struct heavy_hitter *heavy_hitters = NULL;

// stores the length of the heavy_hitters array
static int hh_len = 0;

// keeps track of whether or not the atexit has been registered
static int atexit_installed = 0;

/// free_hh()
///    Frees heavy hitter array. Used as an atexit function

void free_hh(void) {
    free(heavy_hitters);
}

/// m61_malloc(sz, file, line)
///    Return a pointer to `sz` bytes of newly-allocated dynamic memory.
///    The memory is not initialized. If `sz == 0`, then m61_malloc may
///    either return NULL or a unique, newly-allocated pointer value.
///    The allocation request was at location `file`:`line`.

void* m61_malloc(size_t sz, const char *file, int line) {
    (void) file, (void) line;   // avoid uninitialized variable warnings
    if (!atexit_installed) {
        atexit(free_hh);
        atexit_installed = 1;
    }
    // ensure a non-zero size
    if (sz) {
        // get the total size of the memory to be allocated
        size_t total_sz = sizeof(struct header) + sz + strlen(ENDMARKER) + 1;

        // add padding to preserve alignment
        int excess = total_sz % 16;
        if (excess) {
            total_sz += 16 - excess;
        }

        // ensure there was no integer overflow
        if (total_sz <= sz) {
            // if there was, increment nfail and add the fail size
            statistics.nfail ++;
            statistics.fail_size += sz;

            // return a NULL pointer
            return NULL;
        }

        // allocate all of the memory for the metadata and payload
        void *ptr = base_malloc(total_sz);

        // ensure base_malloc didn't return NULL
        if (!ptr) {
            // if it did, increment nfail and add the fail size
            statistics.nfail ++;
            statistics.fail_size += sz;

            // return the NULL pointer
            return ptr;
        }

        // initialize the metadata and store pertinent information
        struct header *metadata = (struct header*) ptr;
        metadata->sz = sz;
        metadata->next = NULL;
        metadata->prev = NULL;
        metadata->file = file;
        metadata->line = line;

        // get the payload location and store it in the metadata
        void *payload = (void*) ((char*) ptr + sizeof(struct header));
        metadata->payload = payload;

        // add the terminator canary immediately after the payload
        char *end = (char*) payload + sz;
        strcpy(end, ENDMARKER);

        // update the statistics
        statistics.nactive ++;
        statistics.active_size += sz;
        statistics.total_size += sz;
        statistics.ntotal ++;

        // check to see if the payload is the heap_min and store it
        if (statistics.heap_min) {
            if (statistics.heap_min > (char*) payload) {
                statistics.heap_min = (char*) payload;
            }
        }
        else {
            statistics.heap_min = (char*) payload;
        }

        // check to see if the payload is the heap_max and store it
        if (statistics.heap_max) {
            if (statistics.heap_max < (char*) payload + sz) {
                statistics.heap_max = (char*) payload + sz;
            }
        }
        else {
            statistics.heap_max = (char*)payload + sz;
        }

        // ensure the list has started before trying to access any values
        if (metadata_list) {
            // set last block's metadata to reflect whether this block is active
            metadata_list->prev = metadata;
        }

        // add this block's metadata to the linked list
        metadata->next = metadata_list;
        metadata_list = metadata;

        // just so we can know whether or not we were able to store hh info
        int found = 0;
    
        // iterate over heavy_hitters array
        for (int i = 0; i < hh_len; i ++) {
            // if we find the file and line, update allocations and bytes
            if (heavy_hitters[i].file == file &&
                heavy_hitters[i].line == line) {
                heavy_hitters[i].allocations ++;
                heavy_hitters[i].sz += sz;
                found = 1;

                // break out of loop
                break;
            }
        }

        // if we didn't find a place for the hh_info, realloc for more space
        if (!found) {
            hh_len ++;
            heavy_hitters = realloc(heavy_hitters,
                                    sizeof(struct heavy_hitter) * hh_len);
            heavy_hitters[hh_len - 1].sz = sz;
            heavy_hitters[hh_len - 1].allocations = 1;
            heavy_hitters[hh_len - 1].line = line;
            heavy_hitters[hh_len - 1].file = file;
        }

        // return the payload
        return payload;
    }
    // if the size is 0, return a NULL pointer
    else {
        return NULL;
    }
}

/// determine_error(ptr, file, line, err_type)
///    Determines if ptr is within another allocated block. If it is,
///    it will print the proper error message. If not, it will print a
///    standard error without extra information. This function takes a 
///    string called err_type, that allows the error message to differentiate 
///    between free and realloc errors.

void determine_error(void *ptr, const char *file, int line, char err_type[]) {
    // create a cursor to iterate over list
    struct header *cursor = metadata_list;
    
    // loop over the list while the cursor is not NULL
    while (cursor) {
        // if pointer is inside block, tell user and abort
        if ((char*) ptr > (char*) cursor &&
            (char*) ptr < (char*) cursor + cursor->sz) {
            fprintf(stderr, "MEMORY BUG: %s:%d: invalid %s of pointer %p, not"
                            " allocated\n", file, line, err_type, ptr);
            fprintf(stderr, "  %s:%i: %p is %zu bytes inside a %zu byte "
                            "region allocated here\n",
                            cursor->file, cursor->line, ptr,
                            (char*) ptr - (char*) cursor->payload, cursor->sz);
            
            abort();
        }

        // set the cursor to the next block
        cursor = cursor->next;
    }

    // if no specific error found, just tell the user there was an error
    fprintf(stderr, "MEMORY BUG: %s:%d: invalid %s of pointer %p\n",
                    file, line, err_type, ptr);

    abort();
}

/// m61_free(ptr, file, line)
///    Free the memory space pointed to by `ptr`, which must have been
///    returned by a previous call to m61_malloc and friends. If
///    `ptr == NULL`, does nothing. The free was called at location
///    `file`:`line`.

void m61_free(void *ptr, const char *file, int line) {
    (void) file, (void) line;   // avoid uninitialized variable warnings

    // ensure the pointer isn't NULL
    if (ptr) {
        // ensure the pointer is in the heap
        if ((char*) ptr < statistics.heap_min ||
            (char*) ptr > statistics.heap_max) {
            fprintf(stderr, "MEMORY BUG: %s:%d: invalid free of pointer %p, "
                            "not in heap\n", file, line, ptr);
            abort();
        }

        // get the pointer's metadata
        struct header *allocation_info = (struct header*) ptr - 1;
        
        // ensure metadata's payload matches ptr and that the block is active
        if (((uintptr_t) allocation_info & 15) == 0 &&
            allocation_info->payload == ptr &&
            metadata_list &&
            (!allocation_info->prev ||
             allocation_info->prev->next == allocation_info) &&
            (!allocation_info->next ||
             allocation_info->next->prev == allocation_info)) {
            // ensure the terminator canary is there
            if (strcmp((char*) ptr + allocation_info->sz, ENDMARKER) != 0){
                fprintf(stderr, "MEMORY BUG: %s:%d: detected wild write "
                                "during free of pointer %p\n", file, line, ptr);
                abort();
            }
            
            // update the active allocated memory statistics
            statistics.nactive--;
            statistics.active_size -= allocation_info->sz;

            // check if this is the head of the list
            if (allocation_info == metadata_list) {
                // if it has a next member, set that to the head of the list
                if (metadata_list->next) {
                    metadata_list = metadata_list->next;
                }
                // otherwise set it to NULL
                else {
                    metadata_list = NULL;
                }
            }
            else {
                // update the linked list to remove references to freed block
                if (allocation_info->next) {
                    allocation_info->next->prev = allocation_info->prev;
                }
                if (allocation_info->prev) {
                    allocation_info->prev->next = allocation_info->next;
                }
            }
            
            // free the memory
            base_free(allocation_info);
        }
        // if it gets here, the free is invalid
        else {
            determine_error(ptr, file, line, "free\0");
        }
    }
}


/// m61_realloc(ptr, sz, file, line)
///    Reallocate the dynamic memory pointed to by `ptr` to hold at least
///    `sz` bytes, returning a pointer to the new block. If `ptr` is NULL,
///    behaves like `m61_malloc(sz, file, line)`. If `sz` is 0, behaves
///    like `m61_free(ptr, file, line)`. The allocation request was at
///    location `file`:`line`.

void* m61_realloc(void *ptr, size_t sz, const char *file, int line) {
    // create new pointer and allocate memory to it
    void *new_ptr = m61_malloc(sz, file, line);

    // ensure the new pointer isn't NULL and the pointer passed in isn't NULL
    if (ptr && new_ptr) {
        // ensure the pointer is in the heap
        if ((char*) ptr < statistics.heap_min ||
            (char*) ptr > statistics.heap_max) {
            fprintf(stderr, "MEMORY BUG: %s:%d: invalid realloc of "
                            "pointer %p, not in heap\n", file, line, ptr);
            abort();
        }

        // get the metadata for the pointer to be realloc'd
        struct header *allocation_info = (struct header*) ptr - 1;
        
        // ensure proper alignment and that the block hasn't been freed
        if (((uintptr_t) allocation_info & 15) != 0 ||
            allocation_info->payload != ptr ||
            !metadata_list ||
            (allocation_info->prev &&
             allocation_info->prev->next != allocation_info) ||
            (allocation_info->next &&
             allocation_info->next->prev != allocation_info)) {
            determine_error(ptr, file, line, "realloc\0");
        }

        // copy the memory from the old pointer
        if (allocation_info->sz < sz) {
            // if the new size is bigger, use the size of the old allocation
            memcpy(new_ptr, ptr, allocation_info->sz);
        }
        else {
            // if the new size is smaller, use new size to avoid buffer overflow
            memcpy(new_ptr, ptr, sz);
        }
    }
    // free the old block
    m61_free(ptr, file, line);
    return new_ptr;
}


/// m61_calloc(nmemb, sz, file, line)
///    Return a pointer to newly-allocated dynamic memory big enough to
///    hold an array of `nmemb` elements of `sz` bytes each. The memory
///    is initialized to zero. If `sz == 0`, then m61_malloc may
///    either return NULL or a unique, newly-allocated pointer value.
///    The allocation request was at location `file`:`line`.

void *m61_calloc(size_t nmemb, size_t sz, const char *file, int line) {
    // initialize pointer to NULL
    void *ptr = NULL;

    // calculate total size
    size_t total_sz = nmemb * sz;

    // ensure multiplying the size by nmemb doesn't cause integer overflow
    if (total_sz / sz == nmemb) {
        // allocate the memory for the pointer
        ptr = m61_malloc(nmemb * sz, file, line);
    }

    // ensure the pointer isn't NULL
    if (ptr) {
        // write zeroes in memory for the new block
        memset(ptr, 0, total_sz);
    }
    // if it is NULL, the calloc failed
    else {
        // update statistics to reflect failed allocation
        statistics.nfail ++;
        statistics.fail_size += nmemb * sz;
    }

    // return the pointer
    return ptr;
}


/// m61_getstatistics(stats)
///    Store the current memory statistics in `*stats`.

void m61_getstatistics(struct m61_statistics *stats) {
    // Stub: set all statistics to enormous numbers
    memset(stats, 255, sizeof(struct m61_statistics));

    // set the pointer's value to the global statistics struct
    *stats = statistics;
}


/// m61_printstatistics()
///    Print the current memory statistics.

void m61_printstatistics(void) {
    struct m61_statistics stats;
    m61_getstatistics(&stats);

    printf("malloc count: active %10llu   total %10llu   fail %10llu\n",
           stats.nactive, stats.ntotal, stats.nfail);
    printf("malloc size:  active %10llu   total %10llu   fail %10llu\n",
           stats.active_size, stats.total_size, stats.fail_size);
}


/// m61_printleakreport()
///    Print a report of all currently-active allocated blocks of dynamic
///    memory.

void m61_printleakreport(void) {
    // create a cursor to iterate over linked list
    struct header *cursor = metadata_list;

    // iterate over linked list of metadata
    while (cursor) {
        // if the block is active, print out the block's information
        printf("LEAK CHECK: %s:%i: allocated object %p with size %zu\n",
               cursor->file, cursor->line, cursor->payload, cursor->sz);
        // set cursor to the next item in list
        cursor = cursor->next;
    }
}

/// compare_hh(a, b)
///    Compare two heavy hitters by bytes allocated

int compare_hh(const void *a, const void *b) {
    struct heavy_hitter *hh1 = (struct heavy_hitter*) a;
    struct heavy_hitter *hh2 = (struct heavy_hitter*) b;
    if (hh1->sz > hh2->sz) return -1;
    else if (hh1->sz < hh2->sz) return 1;
    else return 0;
}

void m61_printheavyhitters(void) {
    // sort heavy hitters
    qsort(heavy_hitters, hh_len, sizeof(struct heavy_hitter), compare_hh);

    // create strings for printing out HH info
    char *byte_str = (char*) malloc(1);
    char *alloc_str = (char*) malloc(1);
    *byte_str = '\0';
    *alloc_str = '\0';

    // iterate over linked list of metadata
    for (int i = 0; i < hh_len; i ++) {
        // get byte percentage
        float byte_pct = (float) heavy_hitters[i].sz /
                         (float) statistics.total_size * 100.;

        // if allocated 10% or more, add it to the byte string
        if (byte_pct >= 10.) {
            asprintf(&byte_str, "%sHEAVY HITTER: %s:%i: %zu bytes (~%.2f%%)\n",
                                byte_str, heavy_hitters[i].file,
                                heavy_hitters[i].line, heavy_hitters[i].sz,
                                byte_pct);
        }

        // get allocation percentage
        float alloc_pct = (float) heavy_hitters[i].allocations /
                          (float) statistics.ntotal * 100.;

        // if made 10% or more of all allocations, add it to the alloc string
        if (alloc_pct >= 10.) {
            asprintf(&alloc_str,
                     "%sHEAVY HITTER: %s:%i: %i allocations (~%.2f%%)\n",
                     alloc_str, heavy_hitters[i].file, heavy_hitters[i].line,
                     heavy_hitters[i].allocations, alloc_pct);
        }
    }

    // print everything
    printf("BYTE HEAVY HITTERS\n%s", byte_str);
    printf("Total bytes allocated: %llu\n\n", statistics.total_size);
    printf("ALLOCATION COUNT HEAVY HITTERS\n%s", alloc_str);
    printf("Total number of allocations: %llu\n", statistics.ntotal);

    // free the strings and the heavy_hitters array
    free(byte_str);
    free(alloc_str);
}