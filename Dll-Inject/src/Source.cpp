#include "PROCBLOCK.h"
#include <stdio.h>
#include <iostream>
#include <vector>
#include <Psapi.h>

//to give all necessary privileges to this process
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

inline bool file_exists(const const char* name) {
	struct stat buffer;
	return (stat(name, &buffer) == 0);
}

BOOL inject(HANDLE hProcess, TCHAR* full_dll_path) {

	if (!file_exists(full_dll_path)) {
		printf("[-] Dll file does not exist \n");
		return FALSE;
	}
	DWORD size = strlen(full_dll_path);

	LPVOID remote_dll_path, RemoteAddress=NULL;
	if (!(remote_dll_path= (LPVOID)VirtualAllocEx(hProcess, &RemoteAddress, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
		printf("[!] Allocating memory for the remote process failed %d\n", GetLastError());
		return FALSE;
	}
	printf("[+] Allocated memory offset: 0x%08x\n\n", (DWORD)remote_dll_path);
	if (!WriteProcessMemory(hProcess, remote_dll_path, full_dll_path, size, NULL)) {
		printf("[-] Could not write dll path to the remote process %d\n", GetLastError());
		return FALSE;
	}
	printf("[+] Wrote dllpath to the remote process\n");

	//
	HMODULE hKernel32;
	if (!(hKernel32 = GetModuleHandleA("kernel32.dll")))
	{
		printf("[!] Could not load kernel32.dll %d\n", GetLastError());
		return FALSE;
	}

	printf("[+] Loaded kernel32.dll handle\n");
	LPVOID LoadLibraryAddress = GetProcAddress(hKernel32, "LoadLibraryA");
	if (LoadLibraryAddress == NULL)
	{
		printf("[-] Could not load LoadLibraryA %d\n", GetLastError());
		return FALSE;
	}
	printf("[+] Loaded loadLibrary handle\n\n");

	DWORD threadId;
	HANDLE hThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryAddress, remote_dll_path, 0, &threadId);
	printf("[*] Attempting to create the thread with PID: %d\n", threadId);
	if (hThread == NULL)
	{
		printf("[!] Could not create remote thread %d\n", GetLastError());
		return FALSE;
	}
	printf("[+] Thread with PID %d is running...\n", threadId);

	printf("[*] waiting for thread to execute\n");
	DWORD result = WaitForSingleObject(hThread, 7 * 1000);

	if (!VirtualFreeEx(hProcess, (LPVOID)remote_dll_path, size, MEM_DECOMMIT)) {
		printf("[-] Could not decommit the used memory %d\n", GetLastError());
		return FALSE;
	}

	printf("[+] Decommited allocated memory in the remote process\n");
	if (!VirtualFreeEx(hProcess, (LPVOID)remote_dll_path, NULL, MEM_RELEASE)) {
		printf("[-] Could not free the used memory %d\n", GetLastError());
		return FALSE;
	}
	printf("[+] Freed allocated memory in the remote process\n");

	return TRUE;
}

int main(int argc, char *argv[]) {
	enable_priv();
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	HANDLE hProcess=NULL;
	DWORD act, PID;
	PROCESSENTRY32 pe32;
	char proc_path[MAX_PATH] = {};
	
	std::vector<LPROCBLOCK> proc_list;
	if (argc < 2) {
		printf("Usage: 1nj3ct0r.exe full_dll_path");
		ExitProcess(0);
	}


	Process32First(hSnap, &pe32);
	printf("[*] List Of Available Process: \n");
	int i = 0;
	do {
		LPROCBLOCK p_block = new PROCBLOCK;
		if (p_block->hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID)) {
			GetModuleFileNameEx(p_block->hProcess, NULL, (LPSTR)proc_path, MAX_PATH);
			p_block->pe32 = pe32;
			p_block->full_name = (LPSTR)proc_path;
			printf("[*] %d\t->\tProc name: %s\n", pe32.th32ProcessID, pe32.szExeFile);
			p_block->qId = i;
			proc_list.push_back(p_block);
		}
		//CloseHandle(p_block->hProcess);
		i++;
	} while (Process32Next(hSnap, &pe32));

	printf("[*] Select the PID of the target process : ");
	std::cin >> PID;
	BOOL success = FALSE;
	for (int i = 0; i < proc_list.size();i++) {
		if (proc_list[i]->pe32.th32ProcessID == PID) {
			success = inject(proc_list[i]->hProcess, argv[1]);
			break;
		}
	}
	char* msg = success == TRUE ? "[+] Success" : "[-] Failed";
	printf("%s\n", msg);
	for (int i = 0; i < proc_list.size(); i++) {
		CloseHandle(proc_list[i]->hProcess);
	}
	return 0;
	
}
