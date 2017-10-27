#include <stdio.h>
#include <stdlib.h>
#include <cuda.h>
#include <cuda_runtime_api.h>
#include <unistd.h>

#define MUTEX_LOCK(lock) while (atomicExch((int*)(&(lock)),1));
#define MUTEX_UNLOCK(lock) { atomicExch((int*)(&(lock)),0);}

struct toss
{
  volatile int flag;
  int _lock;
  __device__ void toggle();
  __device__ void check_and_return();
};

__device__ void mysleep(int64_t num_cycles)
{
  int64_t cycles = 0;
  int64_t start = clock64();
  while(cycles < num_cycles) {
    cycles = clock64() - start;
  }
}

__global__ void mywrapper(int cmd, struct toss* ptr, int* d_a) 
{
  switch(cmd) {
    case 0:
      ptr->toggle();
      break;
    case 1:
      ptr->check_and_return();
      break;
    case 2:
      ptr->flag = 0;
      ptr->_lock = 0;
      break;
  }
}

__device__ void toss::toggle() {
  printf("begin of toggle:%d\n", flag);
  if(flag == 0)
    flag = 1;
  else
    flag = 0;
  printf("end of toggle:%d\n", flag);
}

__device__ void toss::check_and_return()
{
  printf("begin of check:%d\n", flag);
  while(flag) {
  }
  printf("end of check:%d\n", flag);
}


int main() {
	int a, *d_a;
	int size = sizeof(int);

  cudaStream_t stream1;
  cudaStreamCreateWithFlags(&stream1,cudaStreamNonBlocking);

	cudaMalloc((void**)&d_a, size);
	
	a = 1;

  cudaMemcpy(d_a, &a, size, cudaMemcpyHostToDevice);

  struct toss* mytoss; 
  cudaMalloc((void**)&mytoss, sizeof(struct toss));

  printf("%d\n", a);

  // init
  mywrapper<<< 1,1 >>> (2, mytoss, NULL);

  // toggle
  mywrapper<<< 1,1 >>> (0, mytoss, d_a);

  // check_and_run
  mywrapper<<< 1,1,0,stream1 >>> (1, mytoss, d_a);

  // toggle
  mywrapper<<< 1,1 >>> (0, mytoss, d_a);

  cudaDeviceSynchronize();

  cudaMemcpy(&a, d_a, size, cudaMemcpyDeviceToHost);
	cudaFree(d_a);
  cudaStreamDestroy(stream1);
  printf("%d\n", a);
  

	return 0;
}
