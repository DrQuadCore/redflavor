
#ifndef __MY_DRV_H__
#define __MY_DRV_H__

#define MYDRV_IOCTL                 0xDA

typedef __u32 my_hnd_t;
#define MY_HANDLE_MASK ((1UL<<32)-1)


struct MYDRV_IOC_PIN_BUFFER_PARAMS
{
    // in
    __u64 addr;
    __u64 size;
    __u64 p2p_token;
    __u32 va_space;
    // out
    my_hnd_t handle;
};

#define MYDRV_IOC_PIN_BUFFER _IOWR(MYDRV_IOCTL, 1, struct MYDRV_IOC_PIN_BUFFER_PARAMS)

struct MYDRV_IOC_GET_INFO_PARAMS
{
    // in
    my_hnd_t handle;
    // out
    __u64 va;
    __u64 mapped_size;
    __u32 page_size;
    __u32 tsc_khz;
    __u64 tm_cycles;
};

#define MYDRV_IOC_GET_INFO _IOWR(MYDRV_IOCTL, 4, struct MYDRV_IOC_GET_INFO_PARAMS *)



#endif // __MY_DRV_H__
