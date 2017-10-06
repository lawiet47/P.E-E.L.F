# Rootkit

This is a rootkit sample that i wrote for fun. It can hide processes, files, the module itself & grant root privileges to the user.

### Usage

The module communicates with the user space using hooked version of `kill` syscall. By sending various signals you can get root shell, hide files & processes.

SIGNAL 62 -> Root Shell

SIGNAL 63 -> Hide the marked pid

SIGNAL 64 -> Unhide the marked pid

### Compile

`make clean && make modules`

### Notes
The module also has stealth ability. It can hide itself from `procfs` & `sysfs`. But after unhiding it again you cannot remove the module.
Therefore the stealth ability is disabled by default but you can easily enable it by calling the `module_hide()` function in the `init` routine.

The module works on 2.6.x 3.x linux kernels. Tested on `CentOS -> 3.10.0, Debian -> 3.13.0, 3.19.0` (x86_64)

If anyone is able to solve the problem about removing the module let me now :)
