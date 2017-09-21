
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/delay.h>
#include <linux/compiler.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/io.h>
#include <linux/timex.h>
#include <linux/timer.h>
#include <linux/pci.h>
#include <linux/highmem.h>

#define DEVNAME "mydrv"

#ifndef random_get_entropy
#define random_get_entropy()	get_cycles()
#endif

#if defined(CONFIG_X86_64) || defined(CONFIG_X86_32)
static inline pgprot_t pgprot_modify_writecombine(pgprot_t old_prot)
{
    pgprot_t new_prot = old_prot;
    pgprot_val(new_prot) &= ~(_PAGE_PSE | _PAGE_PCD | _PAGE_PWT);
    new_prot = __pgprot(pgprot_val(new_prot) | _PAGE_PWT);
    return new_prot;
}
#define get_tsc_khz() cpu_khz // tsc_khz
#elif defined(CONFIG_PPC64)
static inline pgprot_t pgprot_modify_writecombine(pgprot_t old_prot)
{
    return pgprot_writecombine(old_prot);
}
#define get_tsc_khz() (get_cycles()/1000) // dirty hack
#else
#error "X86_64/32 or PPC64 is required"
#endif


#define my_msg(KRNLVL, FMT, ARGS...) printk(KRNLVL DEVNAME ":" FMT, ## ARGS)

#include "mydrv.h"
#include "nv-p2p.h"

static int dbg_enabled = 1;
#define my_dbg(FMT, ARGS...)                               \
    do {                                                    \
        if (dbg_enabled)                                    \
            my_msg(KERN_DEBUG, FMT, ## ARGS);              \
    } while(0)


static int info_enabled = 1;
#define my_info(FMT, ARGS...)                               \
    do {                                                     \
        if (info_enabled)                                    \
            my_msg(KERN_INFO, FMT, ## ARGS);                \
    } while(0)


#define my_err(FMT, ARGS...)                               \
    my_msg(KERN_DEBUG, FMT, ## ARGS)


#define GPU_PAGE_SHIFT   16
#define GPU_PAGE_SIZE    ((u64)1 << GPU_PAGE_SHIFT)
#define GPU_PAGE_OFFSET  (GPU_PAGE_SIZE-1)
#define GPU_PAGE_MASK    (~GPU_PAGE_OFFSET)

struct my_mr {
    struct list_head node;
    my_hnd_t handle;
    u64 offset;
    u64 length;
    u64 p2p_token;
    u32 va_space;
    u32 page_size;
    u64 va;
    u64 mapped_size;
    nvidia_p2p_page_table_t *page_table;
    int cb_flag;
    cycles_t tm_cycles;
    unsigned int tsc_khz;
};
typedef struct my_mr my_mr_t;


struct my_info {
    // simple low-performance linked-list implementation
    struct list_head mr_list;
    struct mutex lock;
};

typedef struct my_info my_info_t;

static int mydrv_major = 0;

static int mydrv_open(struct inode *inode, struct file *filp)
{
    unsigned int minor = MINOR(inode->i_rdev);
    int ret = 0;
    my_info_t *info = NULL;

    my_dbg("minor=%d\n", minor);
    if(minor >= 1) {
        my_err("device minor number too big!\n");
        ret = -ENXIO;
        goto out;
    }

    info = kmalloc(sizeof(my_info_t), GFP_KERNEL);
    if (!info) {
        my_err("can't alloc kernel memory\n");
        ret = -ENOMEM;
        goto out;
    }

    INIT_LIST_HEAD(&info->mr_list);
    mutex_init(&info->lock);

    filp->private_data = info;

out:
    return ret;
}

static void mydrv_get_pages_free_callback(void *data)
{
    my_mr_t *mr = data;
    nvidia_p2p_page_table_t *page_table = NULL;
    my_info("free callback\n");
    // DR: can't take the info->lock here due to potential AB-BA
    // deadlock with internal NV driver lock(s)
    ACCESS_ONCE(mr->cb_flag) = 1;
    wmb();
    page_table = xchg(&mr->page_table, NULL);
    if (page_table) {
        nvidia_p2p_free_page_table(page_table);
        barrier();
    } else {
        my_err("ERROR: free callback, page_table is NULL\n");
    }
}

#define VENDOR_ID 0x10de
#define PROD_ID 0x11fa

static int mydrv_test(my_info_t *info, void __user *_params)
{
    struct MYDRV_IOC_PIN_BUFFER_PARAMS params = {0};
    int ret = 0;
    struct nvidia_p2p_page_table *page_table = NULL;
    u64 page_virt_start;
    u64 page_virt_end;
    size_t rounded_size;
    my_mr_t *mr = NULL;
    cycles_t ta, tb;

    uint64_t* tmp;

    struct pci_dev* pdev = NULL;
    pdev = pci_get_device(VENDOR_ID, PROD_ID, pdev);

    if(pdev == NULL)
      my_info("pdev == NULL\n");
    else
      my_info("pdev != NULL\n");

    if (copy_from_user(&params, _params, sizeof(params))) {
        my_err("copy_from_user failed on user pointer %p\n", _params);
        ret = -EFAULT;
        goto out;
    }

    if (!params.addr) {
        my_err("NULL device pointer\n");
        ret = -EINVAL;
        goto out;
    }

    mr = kmalloc(sizeof(my_mr_t), GFP_KERNEL);
    if (!mr) {
        my_err("can't alloc kernel memory\n");
        ret = -ENOMEM;
        goto out;
    }
    memset(mr, 0, sizeof(*mr));

    // do proper alignment, as required by RM
    page_virt_start  = params.addr & GPU_PAGE_MASK;
    //page_virt_end    = (params.addr + params.size + GPU_PAGE_SIZE - 1) & GPU_PAGE_MASK;
    page_virt_end    = params.addr + params.size - 1;
    rounded_size     = page_virt_end - page_virt_start + 1;
    //rounded_size     = (params.addr & GPU_PAGE_OFFSET) + params.size;

    mr->offset       = params.addr & GPU_PAGE_OFFSET;
    mr->length       = params.size;
    mr->p2p_token    = params.p2p_token;
    mr->va_space     = params.va_space;
    mr->va           = page_virt_start;
    mr->mapped_size  = rounded_size;
    mr->page_table   = NULL;
    mr->cb_flag      = 0;
    mr->handle       = random_get_entropy() & MY_HANDLE_MASK; // this is a hack, we need something really unique and randomized

    my_info("invoking nvidia_p2p_get_pages(va=0x%llx len=%lld p2p_tok=%llx va_tok=%x)\n",
             mr->va, mr->mapped_size, mr->p2p_token, mr->va_space);

    ta = get_cycles();
    ret = nvidia_p2p_get_pages(0, 0, mr->va, mr->mapped_size, &page_table,
    //ret = nvidia_p2p_get_pages(mr->p2p_token, mr->va_space, mr->va, mr->mapped_size, &page_table,
                               mydrv_get_pages_free_callback, mr);
    tb = get_cycles();
    if (ret < 0) {
        my_err("nvidia_p2p_get_pages(va=%llx len=%lld ) failed [ret = %d]\n",
                mr->va, mr->mapped_size, ret);
        goto out;
    }
    mr->page_table = page_table;
    mr->tm_cycles = tb - ta;
    mr->tsc_khz = get_tsc_khz();

    //tmp = ioremap((page_table->pages[0])->physical_address, sizeof(uint64_t));
    //my_info("YHOON:(pa=0x%llx) %u\n", (page_table->pages[0])->physical_address, *tmp);
    //*tmp = 3;

    //my_info("YHOON:(pa=0x%llx) %u\n", (page_table->pages[0])->physical_address, *tmp);

    // check version before accessing page table
    
    if (!NVIDIA_P2P_PAGE_TABLE_VERSION_COMPATIBLE(page_table)) {
        my_err("incompatible page table version 0x%08x\n", page_table->version);
        goto out;
    }

    switch(page_table->page_size) {
    case NVIDIA_P2P_PAGE_SIZE_4KB:
        mr->page_size = 4*1024;
        break;
    case NVIDIA_P2P_PAGE_SIZE_64KB:
        mr->page_size = 64*1024;
        break;
    case NVIDIA_P2P_PAGE_SIZE_128KB:
        mr->page_size = 128*1024;
        break;
    default:
        my_err("unexpected page_size\n");
        ret = -EINVAL;
        goto out;
    }

    // we are not really ready for a different page size
    if(page_table->page_size != NVIDIA_P2P_PAGE_SIZE_64KB) {
        my_err("nvidia_p2p_get_pages assumption of 64KB pages failed size_id=%d\n", page_table->page_size);
        ret = -EINVAL;
        goto out;
    }
    {
        int i;
        my_dbg("page table entries: %d\n", page_table->entries);
        for (i=0; i<page_table->entries; ++i) {
            my_dbg("page[%d]=0x%016llx\n", i, page_table->pages[i]->physical_address);
        }
    }


    // here a typical driver would use the page_table to fill in some HW
    // DMA data structure

    params.handle = mr->handle;

    mutex_lock(&info->lock);
    list_add(&mr->node, &info->mr_list);
    mutex_unlock(&info->lock);

out:

    if (ret && mr && mr->page_table) {
        my_err("error, calling p2p_put_pages\n");
        nvidia_p2p_put_pages(mr->p2p_token, mr->va_space, mr->va, mr->page_table);
        page_table = NULL;
        mr->page_table = NULL;
    }

    if (ret && mr) {
        kfree(mr);
        memset(mr, 0, sizeof(*mr));
        mr = NULL;
    }

    if (!ret && copy_to_user(_params, &params, sizeof(params))) {
        my_err("copy_to_user failed on user pointer %p\n", _params);
        ret = -EFAULT;
    }

    //my_info("AFTER4\n");
    //mutex_lock(&info->lock);
    //tmp = (mr->page_table->pages[0])->physical_address;
    //my_info("AFTER2: 0x%016llx\t%d\n", (mr->page_table->pages[0])->physical_address, tmp[0] );
    //mutex_unlock(&info->lock);

    return ret;

}




static int mydrv_ioctl(struct inode *inode, struct file *filp, unsigned int cmd, unsigned long arg)
{
    int ret = 0;
    my_info_t *info = filp->private_data;
    void __user *argp = (void __user *)arg;

    my_dbg("ioctl called (cmd 0x%x)\n", cmd);

    if (_IOC_TYPE(cmd) != MYDRV_IOCTL) {
        my_err("malformed IOCTL code type=%08x\n", _IOC_TYPE(cmd));
        return -EINVAL;
    }

    switch (cmd) {
    case MYDRV_IOC_PIN_BUFFER:
        ret = mydrv_test(info, argp);
        break;

    default:
        my_err("unsupported IOCTL code\n");
        ret = -ENOTTY;
    }
    return ret;
}
#ifdef HAVE_UNLOCKED_IOCTL
static long mydrv_unlocked_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    return mydrv_ioctl(0, filp, cmd, arg);
}
#endif



struct file_operations mydrv_fops = {
//    .owner    = THIS_MODULE,

#ifdef HAVE_UNLOCKED_IOCTL
    .unlocked_ioctl = mydrv_unlocked_ioctl,
#else
    .ioctl    = mydrv_ioctl,
#endif
    .open     = mydrv_open,
//    .release  = mydrv_release,
//    .mmap     = mydrv_mmap
};

static int __init mydrv_init(void)
{
    int result;

    result = register_chrdev(mydrv_major, DEVNAME, &mydrv_fops);
    if (result < 0) {
        my_err("can't get major %d\n", mydrv_major);
        return result;
    }
    if (mydrv_major == 0) mydrv_major = result; /* dynamic */

    my_msg(KERN_INFO, "device registered with major number %d\n", mydrv_major);
    my_msg(KERN_INFO, "dbg traces %s, info traces %s", dbg_enabled ? "enabled" : "disabled", info_enabled ? "enabled" : "disabled");

    //mydrv_init_devices();/* fills to zero the device array */

    return 0;
}


static void __exit mydrv_cleanup(void)
{
    my_msg(KERN_INFO, "unregistering major number %d\n", mydrv_major);

    /* cleanup_module is never called if registering failed */
    unregister_chrdev(mydrv_major, DEVNAME);
}


module_init(mydrv_init);
module_exit(mydrv_cleanup);

