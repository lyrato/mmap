// Linux Device Driver Template/Skeleton with mmap
// Kernel Module
#include <linux/module.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <asm/uaccess.h>
#include <asm/io.h>
#include <linux/vmalloc.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <asm/pgtable.h>


#include <linux/mm.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/init_task.h>
#include <linux/fs.h>
#include <linux/mqueue.h>
#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/module.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/mm_types.h>
#include <linux/rbtree.h>
#include <linux/rwsem.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/cpumask.h>

#include <asm/atomic.h>
#include <asm/pgtable.h>
#include <linux/bootmem.h>
#include <linux/linkage.h>
#include <linux/bitops.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/string.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/kgdb.h>
#include <linux/smp.h>
#include <linux/io.h>

#include <asm/stackprotector.h>
#include <asm/perf_event.h>
#include <asm/mmu_context.h>
#include <asm/hypervisor.h>
#include <asm/processor.h>
#include <asm/sections.h>
#include <linux/topology.h>
#include <linux/cpumask.h>
#include <asm/pgtable.h>
#include <asm/atomic.h>
#include <asm/proto.h>
#include <asm/setup.h>
#include <asm/apic.h>
#include <asm/desc.h>
#include <asm/i387.h>
#include <asm/mtrr.h>
#include <linux/numa.h>
#include <asm/asm.h>
#include <asm/cpu.h>
#include <asm/mce.h>
#include <asm/msr.h>
#include <asm/pat.h>

#ifdef CONFIG_X86_LOCAL_APIC
#include <asm/uv/uv.h>
#endif



#define SKELETON_MAJOR 240
#define SKELETON_NAME "skeleton"
#define CASE1 1
#define CASE2 2
static unsigned int counter = 0;
static char string [128];
static int data;

static unsigned int *kmalloc_area = NULL;
static unsigned int *kmalloc_ptr = NULL;

#define LEN (64*1024)
unsigned long virt_addr;
DECLARE_WAIT_QUEUE_HEAD(skeleton_wait);
static int data_not_ready = 0;
// open function - called when the "file" /dev/skeleton is opened in userspace
static int skeleton_open (struct inode *inode, struct file *file) 
{
 	printk("skeleton_openn");
 	return 0;
}
// close function - called when the "file" /dev/skeleton is closed in userspace 
static int skeleton_release (struct inode *inode, struct file *file)
{
	 printk("skeleton_releasen");
	 return 0;
}
// read function called when from /dev/skeleton is read
static ssize_t skeleton_read (struct file *file, char *buf,
                                  size_t count, loff_t *ppos) 
{
	int len, err;
    while (data_not_ready)
	{
	    interruptible_sleep_on(&skeleton_wait);
	}
	if( counter <= 0 )
	    return 0;
	err = copy_to_user(buf,string,counter);
	if (err != 0)
	     return -EFAULT;
	len  = counter;
	counter = 0;
	return len;
}

static ssize_t skeleton_write (struct file *file, const char *buf,
                                   size_t count, loff_t *ppos) 
{
	int err;
	err = copy_from_user(string,buf,count);
	if (err != 0)
	   return -EFAULT;
	counter += count;
	return count;
}

static int skeleton_ioctl(struct inode *inode, struct file *file,
                             unsigned int cmd, unsigned long arg)
{
	int retval = 0;
	switch ( cmd ) 
	{
	   case CASE1:/* for writing data to arg */
 	      if (copy_from_user(&data, (int *)arg, sizeof(int)))
 	          return -EFAULT;
	       break;
	  case CASE2:/* for reading data from arg */
	      if (copy_to_user((int *)arg, &data, sizeof(int)))
	          return -EFAULT;
	      break;
	  default:
	   retval = -EINVAL;
	}
	return retval;
}
#ifndef VMALLOC_VMADDR
#define VMALLOC_VMADDR(x) ((unsigned long)(x))
#endif

volatile void *virt_to_kseg(volatile void *address) 
{
	pgd_t *pgd; pmd_t *pmd; pte_t *ptep, pte;
	unsigned long va, ret = 0UL;
	va=VMALLOC_VMADDR((unsigned long)address);
	/* get the page directory. Use the kernel memory map. */
	//pgd = my_pgd_offset_k(va);
	/* check whether we found an entry */
	if (!pgd_none(*pgd)) 
	{
		pud_t *pud = pud_offset(pgd, va);  
		pmd = pmd_offset(pud, va);

	     /* check whether we found an entry */
		if (!pmd_none(*pmd)) 
		{
	        /* get a pointer to the page table entry */
			ptep = pte_offset_kernel(pmd, va);
		    pte = *ptep;
		    /* check for a valid page */
		    if (pte_present(pte)) 
		    {
		        /* get the address the page is refering to */
		    	ret = (unsigned long)page_address(pte_page(pte));
		        /* add the offset within the page to the page address */
		   		ret |= (va & (PAGE_SIZE -1));
		    }
	     }
    }
     return((volatile void *)ret);
}
void skeleton_vma_open(struct vm_area_struct *vma)
{
	printk(KERN_NOTICE "Simple VMA open, virt %lx, phys %lx\n",
			vma->vm_start, vma->vm_pgoff << PAGE_SHIFT);
}

void skeleton_vma_close(struct vm_area_struct *vma)
{
	printk(KERN_NOTICE "Simple VMA close.\n");
}

static struct vm_operations_struct skeleton_remap_vm_ops = {
	.open =  skeleton_vma_open,
	.close = skeleton_vma_close,
};
static int skeleton_mmap(struct file * filp, struct vm_area_struct * vma)
{
	int ret;
	ret = remap_pfn_range(vma,
               vma->vm_start,
               virt_to_phys((void*)((unsigned long)kmalloc_area)) >> PAGE_SHIFT,
               vma->vm_end-vma->vm_start,
               PAGE_SHARED);
     if(ret != 0) 
	   {
         return -EAGAIN;
     }
     vma->vm_ops = &skeleton_remap_vm_ops;
     skeleton_vma_open(vma);
     return 0;
}
// define which file operations are supported
struct file_operations skeleton_fops = 
{
	 .owner = THIS_MODULE,
	 .llseek = NULL,
	 .read  = skeleton_read,
	 .write = skeleton_write,
	 .readdir = NULL,
	 .poll  = NULL,
	 .ioctl = skeleton_ioctl,
	 .mmap  = skeleton_mmap,
	 .open  = skeleton_open,
	 .flush = NULL,
	 .release = skeleton_release,
	 .fsync = NULL,
	 .fasync = NULL,
	 .lock  = NULL,
};
// initialize module
static int __init skeleton_init_module (void) 
{
	int i;
	unsigned int tmp,tmp2;
	printk("initializing modulen\n");
	 
	i = register_chrdev (SKELETON_MAJOR, SKELETON_NAME, &skeleton_fops);
    if (i != 0) 
		return - EIO;
 
 // reserve memory with kmalloc - Allocating Memory in the Kernel
	kmalloc_ptr = kmalloc(LEN + 2 * PAGE_SIZE, GFP_KERNEL);
	if (!kmalloc_ptr) 
	{
		printk("kmalloc failedn\n");
		return 0;
	}
	kmalloc_area = (unsigned int *)(((unsigned long)kmalloc_ptr + PAGE_SIZE -1) & PAGE_MASK);
	#if 0
	for (virt_addr=(unsigned long)kmalloc_area; virt_addr < (unsigned long)kmalloc_area + LEN;
         virt_addr+=PAGE_SIZE) 
	{
   // reserve all pages to make them remapable
		SetPageReserved(virt_to_page(virt_addr));	
	}
	#endif
	//printk("kmalloc_area at 0x%p (phys 0x%lx)\n", kmalloc_area,
          //  virt_to_phys((void *)virt_to_kseg(kmalloc_area)));
 // fill allocated memory with integers
    tmp = sizeof(int);
    for( i = 0; i < (10 * tmp); i = i + tmp) 
	{
        kmalloc_ptr[i] = (unsigned int)i;
        tmp2 = (unsigned int)kmalloc_ptr[i];
        printk("kmalloc_ptr[%d]=%d\n", i, tmp2);
    }
	return 0;
}
// close and cleanup module
static void __exit skeleton_cleanup_module (void) 
{
	printk("cleaning up modulen");
	kfree(kmalloc_ptr);
	unregister_chrdev (SKELETON_MAJOR, SKELETON_NAME);
}
module_init(skeleton_init_module);
module_exit(skeleton_cleanup_module);
MODULE_AUTHOR("www.captain.at");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Linux Device Driver Template with MMAP");

