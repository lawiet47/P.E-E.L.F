
This is the source code of a program I built to get a better understanding of PE Format, Virtual Addresses and Sections.
You can customize it all the way you want.

The Program contains two modules.

1)Hollow_PE writes all of the contents of the specified process section by section to the new process.

2)Mirror_PE creates a new section in itself, maps that section to the remote process, writes contents of the local executable to that section, calls the specified function from the local executable.

Unfortunately there are still some things i don't quite understand. There are some processes i could not hollow out or map a section to. Like Hollow_PE module does not work with explorer.exe, but works with processes like cmd.exe, chkdsk.exe etc. On the other hand Mirror_PE module does not work with these processes but works with explorer.exe. The reason is unknown to me so if anyone finds out let me now :)


NOTE: I tried to use predefined "ntdef.h" header file but for some weird reason visual studio did not resolve the data types, so i wrote the needed structures in a custom "NTHeaders.h" file.

NOTE #2: You can compile it as a 64bit binary for injecting code to 64 bit processes. There would be some changes you'd need to do before you do this. Like changing some structure types in the function parameters, renaming registers etc. I'd love to make the program check for OS architecture, but I am kinda lazy :) So if you want you can implement it yourself.

NOTE #3: There is a simple shellcode(Shellcode.h) and a small function that i included to test the Hollow_PE & Mirror_PE modules, but you can use whatever code you wanna inject

Compiler Options: `/GS /analyze- /W3 /Zc:wchar_t /ZI /Gm /Od /sdl /Fd"Debug\vc141.pdb" /Zc:inline /fp:precise /D "_MBCS" /errorReport:prompt /WX- /Zc:forScope /RTC1 /Gd /Oy- /MDd /Fa"Debug\" /EHsc /nologo /Fo"Debug\" /Fp"Debug\ZomBozo.pch" /diagnostics:classic`
