// Linux Device Driver Template/Skeleton with mmap
// Userspace test program
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>
#define CASE1 1
#define CASE2 2
#define BUFSIZE 64*1024
//extern  void hello(void);
//extern  global;
//#define USEASCII
main() 
{
	 int i, fd, len, wlen, tmp, tmp2;
	 char string[] = "Skeleton Kernel Module Test";
	 char receive[128];
	 unsigned buffer[BUFSIZE];
	 int data, rdata;
	 char * mptr;
	 size_t size = BUFSIZE;
	 fd = open("/dev/skeleton", O_RDWR | O_SYNC);
	 if( fd == -1) 
	 {
	     printf("open error...\n");
	     exit(0);
	 }
	 // test device write function
	 wlen = strlen(string) + 1;
	 len = write(fd, string, wlen);
	 if( len == -1 )
	 {
		  printf("write error...\n");
		  exit(1);
	 }
	 printf("String '%s' written to /dev/skeleton\n", string);
	 
	 // test device read function
	 len = read(fd, receive, 128);
	 if( len == -1 ) 
	 {
		  printf("read error...n");
		  exit(1);
	 }
	 printf("String '%s' read from /dev/skeleton\n", receive);
	 // test mmap
	 mptr = mmap(0, size, PROT_READ | PROT_WRITE, MAP_FILE | MAP_SHARED, fd, 0);
	 if(mptr == MAP_FAILED) 
	 {
		  printf("mmap() failed\n");
		  exit(1);
	 }
	 
	 memset(buffer, 0, size);
	 // read from the kmalloc area in kernel space
	 memcpy(buffer, mptr, size-1);
	 tmp = sizeof(int);
	 for( i = 0; i < (10 * tmp); i = i + tmp) 
	 {
		  tmp2 = (unsigned int)buffer[i];
		  printf("buffer[%d]=%d\n", i, tmp2);
	 }
	 // test ioctl
	 data = 0x55555555;
	 ioctl(fd, CASE1, &data);
	 ioctl(fd, CASE2, &rdata);
	 printf("IOCTL test: written: '%x' - received: '%x'\n", data, rdata);
	 munmap(mptr, size);
	 close(fd);
}
