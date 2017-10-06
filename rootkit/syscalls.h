asmlinkage int (*unlink)(const char *filename);
asmlinkage int (*unlinkat)(int dirfd, const char *pathname, int flags);
asmlinkage int (*kill)(pid_t pid, int sig);
asmlinkage int (*getdents)(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
asmlinkage int (*getdents64)(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count);
