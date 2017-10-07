This is simply a PoC paper about linux rootkits.
## What is a rootkit?
A rootkit is a collection of computer software, typically malicious, designed to enable access to a
computer or areas of its software that would not otherwise be allowed.
Rootkits are generaly used by malware authors to hide their malicious code.
## How does it work?
Before we get into how they work we should be able to have a basic knowledge of `User
mode`, `Kernel mode` and `syscalls`.
The Computers separate code into different privilege levels. This is done by `Rings`. Rings are
hardware protection mechanisms.

![rings](https://user-images.githubusercontent.com/27059441/31307432-22486786-ab6d-11e7-9f33-a22e38388bf7.png)

There are 4 levels of Rings.(0,1,2,3). Ring 0 is where the kernel and its drivers operate and it's the
most privileged level(Kernel Mode). Ring 1&2 is for privileged code(user programs with I/O access
permissions) and Ring 3 is the level where all the other user programs run(User Mode).
After we power up the computer, it starts in Ring 0. The other levels are initialized afterwards.
## What is a syscall?
Here is a statement from wikipedia page: "*a system call is the programmatic way in which a
computer program requests a service from the kernel of the operating system it is executed on*".

Simply it is a function that's executed by a user program to request a service from the kernel.

![linux_exec_process](https://user-images.githubusercontent.com/27059441/31307486-b13da4f6-ab6d-11e7-8b52-cb8c69ad8235.png)

In this picture we see how a syscall works. `execve` is a wrapper for the `sys_execve`
syscall, provided by `libc`. So when we call the wrapper function like `execve` it goes and finds
the corresponding syscall in the `Syscall Table`(id of the syscall is stored in the `rax` resgister) and
makes a call to it.

**Syscall Table** is a place where the pointers to all of these entries are stored. The rootkit works by
`hooking` these syscalls, meaning, it replaces the syscalls in the Syscall Table with its own
functions.
It does that by locating the `Syscall Table` in the memory first. Then it replaces the pointer pointing
to the actual syscall with a fake one pointing to a malicious function(more details in the code).

![hooked](https://user-images.githubusercontent.com/27059441/31307503-2a109e10-ab6e-11e7-87f3-d5763703d861.png)

This is the state after the rootkit has done it's job.

Here is a little demonstration of how rootkit hides files containing specific substring by hooking `getdents syscall` used to view the contents of a directory (In this case the file_signature is “r0r0_” so any file containing this
substring will be hidden):

Before Rootkit

![before-rootkit](https://user-images.githubusercontent.com/27059441/31307508-43fb9c76-ab6e-11e7-9194-eaf1717bdbec.png)

After Rootkit

![after-rootkit](https://user-images.githubusercontent.com/27059441/31307513-51b099ca-ab6e-11e7-8d02-dd23b62e7b50.png)
