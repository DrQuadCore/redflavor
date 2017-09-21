#include <stdint.h> // for standard [u]intX_t types
#include <stddef.h>

#define GPU_PAGE_SHIFT   16
#define GPU_PAGE_SIZE    (1UL << GPU_PAGE_SHIFT)
#define GPU_PAGE_OFFSET  (GPU_PAGE_SIZE-1)
#define GPU_PAGE_MASK    (~GPU_PAGE_OFFSET)


struct my;
typedef struct my *my_t;

typedef uint32_t my_mh_t;

int my_pin_buffer(my_t g, unsigned long addr, size_t size, uint64_t p2p_token, uint32_t va_space, my_mh_t *handle);

