#include <windows.h>
#include <TlHelp32.h>
typedef struct _process_block {
	DWORD qId;
	PROCESSENTRY32 pe32;
	HANDLE hProcess;
	LPSTR full_name;
} PROCBLOCK, *LPROCBLOCK;
