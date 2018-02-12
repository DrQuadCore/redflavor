#include <stdint.h> // for standard [u]intX_t types
#include <stddef.h>

//#include <inttypes.h>
#include <signal.h>
#define GPU_PAGE_SHIFT   16
#define GPU_PAGE_SIZE    (1UL << GPU_PAGE_SHIFT)
#define GPU_PAGE_OFFSET  (GPU_PAGE_SIZE-1)
#define GPU_PAGE_MASK    (~GPU_PAGE_OFFSET)

#define WAIT_ON_MEM(mem,val)  while(readNoCache(&(mem))!=val);
#define WAIT_ON_MEM_NE(mem,val)  while(readNoCache(&(mem))==val);

#define FIRST_THREAD_IN_BLOCK() ((threadIdx.x + threadIdx.y + threadIdx.z) == 0)
#define BEGIN_SINGLE_THREAD_PART __syncthreads(); if(FIRST_THREAD_IN_BLOCK()) { do
#define BEGIN_SINGLE_THREAD BEGIN_SINGLE_THREAD_PART {
#define END_SINGLE_THREAD_PART while(0); } __syncthreads()
#define END_SINGLE_THREAD  } END_SINGLE_THREAD_PART ;

#define likely(x)    __builtin_expect(!!(x), 1)
#define unlikely(x)  __builtin_expect(!!(x), 0)

#define RAISE_SIGTRAP   raise(SIGTRAP)
/*
 * call stack trace fn
 */

inline void __ASSERT(char const * const func, const char * const file,
                     const int line, const char * const format, ...) {
	char buf[4096] = { 0 };
	char msg[4096] = { 0 };

	sprintf(buf, "\n");
	sprintf(buf, "%s\t%s:%d\n", buf, file, line);
	sprintf(buf, "%s\tAssertion '%s' failed.\n", buf, func);
	va_list args;
	va_start(args, format);
	vsprintf(msg, format, args);
	va_end(args);

	fflush(stdout);
	fflush(stderr);

	fprintf(stderr, "%s\t%s", buf, msg);

	fflush(stdout);
	fflush(stderr);

	RAISE_SIGTRAP;
	abort();
}

#define ASSERT_CUDA(val)												\
    if(unlikely((val))) {__ASSERT(#val, __FILE__, __LINE__, "errno = %3d : %s\n", static_cast<int>(val), cudaGetErrorString(val));}

__forceinline__ __device__ uint16_t readNoCache(const volatile uint16_t* ptr){
  uint16_t val;
  val=*ptr;       
  return val;
}


__forceinline__ __device__ double readNoCache(const volatile double* ptr){
  double val;
  val=*ptr;       
//	asm("ld.cv.f64 %0, [%1];"  : "=d"(val):"l"(ptr));
  return val;
}

__forceinline__ __device__ unsigned char readNoCache(const volatile unsigned char* ptr){
  unsigned char v;
  v = *ptr; 
  return v;
//	asm("ld.cv.u16 %0, [%1];"  : "=h"(val2):"l"(ptr));
//	char2 n;
//	n.x=(char)val2; n.y=(char)val2>>8;
//          return n;
}

__forceinline__ __device__ unsigned int readNoCache(const volatile unsigned int* ptr){
  unsigned int val;
  val=*ptr;       
//	asm("ld.cv.u32 %0, [%1];"  : "=r"(val):"l"(ptr));
  return val;
}

__forceinline__ __device__ int readNoCache(const volatile int* ptr){
  int val;
  val=*ptr;       
  //asm("ld.cv.u32 %0, [%1];"  : "=r"(val):"l"(ptr));
  return val;
}
__forceinline__ __device__ size_t readNoCache(const volatile size_t* ptr){
  size_t val;
  val=*ptr;       
//	if (sizeof(size_t)==8)
//	asm("ld.cv.f64 %0, [%1];"  : "=d"(val):"l"(ptr));
//	else
//	asm("ld.cv.u32 %0, [%1];"  : "=r"(val):"l"(ptr));
  return val;
}

struct my;
typedef struct my *my_t;

typedef uint32_t my_mh_t;

int my_pin_buffer(my_t g, unsigned long addr, size_t size, uint64_t p2p_token, uint32_t va_space, my_mh_t *handle);

