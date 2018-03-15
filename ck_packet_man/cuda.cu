#include <stdio.h>
#include <stdlib.h>
#include <cuda.h>
#include <cuda_runtime_api.h>

__global__ void add(int *a, int *b, int *c, int tmp) {
	*c = *a + *b + tmp;
  printf("add\n");
  printf("%d %d\n", *a, tmp);
}

int main() {
	int a, b, c;
	int *d_a, *d_b, *d_c;
	int size = sizeof(int);

	cudaMalloc((void**)&d_a, size);
	cudaMalloc((void**)&d_b, size);
	cudaMalloc((void**)&d_c, size);
	
	a = 0;
	b = 1;
  c = 2;
	printf("[before]%d %d %d\n", a, b, c);
	cudaMemcpy(d_a, &a, size, cudaMemcpyHostToDevice);
	cudaMemcpy(d_b, &b, size, cudaMemcpyHostToDevice);
	
	add<<< 1, 1 >>>(d_a, d_b, d_c, 4);
		
	cudaMemcpy(&c, d_c, size, cudaMemcpyDeviceToHost);
	printf("[after]%d %d %d\n", a, b, c);
	cudaFree(d_a);
	cudaFree(d_b);
	cudaFree(d_c);

	return 0;
}
