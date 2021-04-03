#include <iostream>
#include <Windows.h>
#include <conio.h>
#include <string>
#include <tlhelp32.h>
#include <winternl.h>
// For SID conversion
#include <sddl.h>
#include <aclapi.h>

using namespace std;


typedef struct _SYSTEM_PROCESS_INFO
{
	ULONG                   NextEntryOffset;
	ULONG                   NumberOfThreads;
	LARGE_INTEGER           Reserved[3];
	LARGE_INTEGER           CreateTime;
	LARGE_INTEGER           UserTime;
	LARGE_INTEGER           KernelTime;
	UNICODE_STRING          ImageName;
	ULONG                   BasePriority;
	HANDLE                  ProcessId;
	HANDLE                  InheritedFromProcessId;
}SYSTEM_PROCESS_INFO, *PSYSTEM_PROCESS_INFO;




void init(string *);
void findProcessInRingOfProc(string);
BOOL ListProcessModules(DWORD);
BOOL ListProcessThreads(DWORD);
BOOL ListProcessHeap(DWORD);
DWORD ListCommandLineW(HANDLE, LPWSTR, UINT);
BOOL FreeLogonSID(PSID);
void Cleanup(PTOKEN_GROUPS);
BOOL GetLogonSID(HANDLE, PSID);
void killProcessByName(const char *);
void ChangePriority(char *, char *);

int main(int argc,char *argv[])
{

	if (argc < 1)
	{
		return 1;
	}
	//cout << argv[0] << '\n';
	//cout << argv[1] << '\n';
	//cout << argv[2] << '\n';


	//if (strcmp(nameOfProcess.c_str(), pe32.szExeFile) == 0)
	//string nameOfProcess;
	//init(&nameOfProcess);
	if (strcmp(argv[1], "-list") == 0)
	{
		findProcessInRingOfProc(argv[2]);
	}
	else if (strcmp(argv[1], "-t") == 0)
	{
		killProcessByName(argv[2]);
	}
	else if (strcmp(argv[1], "-p") == 0)
	{
		ChangePriority(argv[2], argv[3]);
	}
	else if (strcmp(argv[1], "-help") == 0)
	{
		cout << "	-list 'name of process' = show information about processes.\n"
			"	-t 'name of process' = terminating process.\n"
			"	-p 'name of process' = priority class flag: \n"
			"		NORMAL_PRIORITY_CLASS             0x00000020	DEC: 32\n"
			"		IDLE_PRIORITY_CLASS               0x00000040	DEC: 64\n"
			"		HIGH_PRIORITY_CLASS               0x00000080	DEC: 128\n"
			"		REALTIME_PRIORITY_CLASS           0x00000100	DEC: 256";
	}
	_getch();
	return 0;
}


void init(string *str1)
{
	cout << "Enter name of the process: ";
	cin >> *str1;
}

void findProcessInRingOfProc(string nameOfProcess)
{
	HANDLE hProcessSnap;
	HANDLE hProcess;
	PROCESSENTRY32 pe32;
	DWORD dwPriorityClass;
	WCHAR buf[MAX_PATH];
	// Handle to token
	HANDLE hToken = NULL;

	// A 'dummy' initial size of SID to avoid a NULL pointer
	BYTE sidBuffer[256];
	PSID ppsid = (PSID)&sidBuffer;

	// Take a snapshot of all processes in the system.
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		//cout << "CreateToolhelp32Snapshot (of processes)";
	}

	// Set the size of the structure before using it.
	pe32.dwSize = sizeof(PROCESSENTRY32);

	// Retrieve information about the first process,
	// and exit if unsuccessful
	if (!Process32First(hProcessSnap, &pe32))
	{
		//cout << "Process32First";			// show cause of failure
		CloseHandle(hProcessSnap);			// clean the snapshot object
	}

	// Now walk the snapshot of processes, and
	// display information about each process in turn
	do
	{
		if (strcmp(nameOfProcess.c_str(), pe32.szExeFile) == 0)
		{
			buf[0] = 0;
			cout << "\n\n=====================================================";
			cout << "\nPROCESS NAME:  " << pe32.szExeFile;
			cout << "\n-------------------------------------------------------";

			// Retrieve the priority class.
			dwPriorityClass = 0;
			hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
			if (!hProcess == NULL)
			{
				dwPriorityClass = GetPriorityClass(hProcess);
				if (!dwPriorityClass)
					cout << "GetPriorityClass";
			}
			

			// Open a handle to the access token for the calling process
			// that is the currently login access token
			OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hToken);

			cout << "\n  Process ID        = " << pe32.th32ProcessID;
			cout << "\n  Thread count      = " << pe32.cntThreads;
			cout << "\n  Parent process ID = " << pe32.th32ParentProcessID;
			cout << "\n  Priority base     = " << pe32.pcPriClassBase;
			if (dwPriorityClass)
				cout << "\n  Priority class    = " << dwPriorityClass;
			cout << " \n  Command line arg  =";

			if (ListCommandLineW(hProcess, buf, MAX_PATH))
			{
				wprintf(L" %s\n", buf);
			}
			
			// Call the GetLogonSID()
			cout << "\n  The logon SID     = ";
			GetLogonSID(hToken, ppsid);
			
			// List the modules and threads associated with this process
			ListProcessModules(pe32.th32ProcessID);
			ListProcessThreads(pe32.th32ProcessID);
			ListProcessHeap(pe32.th32ProcessID);

			CloseHandle(hProcess);
		}
	} while (Process32Next(hProcessSnap, &pe32));
	//pe32.szExeFile

	// Close the handle lol
	CloseHandle(hToken);
	CloseHandle(hProcessSnap);
}

BOOL ListProcessModules(DWORD dwPID)
{
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32;

	// Take a snapshot of all modules in the specified process.
	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
	if (hModuleSnap == INVALID_HANDLE_VALUE)
	{
		//cout << "CreateToolhelp32Snapshot (of modules)";
		return(FALSE);
	}

	// Set the size of the structure before using it.
	me32.dwSize = sizeof(MODULEENTRY32);

	// Retrieve information about the first module,
	// and exit if unsuccessful
	if (!Module32First(hModuleSnap, &me32))
	{
		cout << "Module32First";  // show cause of failure
		CloseHandle(hModuleSnap);           // clean the snapshot object
		return(FALSE);
	}

	// Now walk the module list of the process,
	// and display information about each module
	do
	{
		cout << "\n\n			 MODULE NAME:     " << me32.szModule;
		cout << "\n			 Executable     = " << me32.szExePath;
		cout << "\n			 Process ID     = " << me32.th32ProcessID;
		cout << "\n			 Ref count (g)  = 0x%04X" << me32.GlblcntUsage;
		cout << "\n			 Ref count (p)  = 0x%04X" << me32.ProccntUsage;
		cout << "\n			 Base address   = 0x%08X" << (DWORD)me32.modBaseAddr;
		cout << "\n			 Base size      = " << me32.modBaseSize;

	} while (Module32Next(hModuleSnap, &me32));

	CloseHandle(hModuleSnap);
	return(TRUE);
}

BOOL ListProcessThreads(DWORD dwOwnerPID)
{
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;

	// Take a snapshot of all running threads  
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return(FALSE);

	// Fill in the size of the structure before using it. 
	te32.dwSize = sizeof(THREADENTRY32);

	// Retrieve information about the first thread,
	// and exit if unsuccessful
	if (!Thread32First(hThreadSnap, &te32))
	{
		cout << "Thread32First"; // show cause of failure
		CloseHandle(hThreadSnap);          // clean the snapshot object
		return(FALSE);
	}

	// Now walk the thread list of the system,
	// and display information about each thread
	// associated with the specified process
	do
	{
		if (te32.th32OwnerProcessID == dwOwnerPID)
		{
			cout << "\n\n			 THREAD ID      = " << te32.th32ThreadID;
			cout << "\n			 Base priority  = " << te32.tpBasePri;
			cout << "\n			 Delta priority = " << te32.tpDeltaPri;
			cout << "\n";
		}
	} while (Thread32Next(hThreadSnap, &te32));

	CloseHandle(hThreadSnap);
	return(TRUE);
}

BOOL ListProcessHeap(DWORD dwPID)
{
	HEAPLIST32 hl;

	HANDLE hHeapSnap = CreateToolhelp32Snapshot(TH32CS_SNAPHEAPLIST, dwPID);

	hl.dwSize = sizeof(HEAPLIST32);

	if (hHeapSnap == INVALID_HANDLE_VALUE)
	{
		printf("CreateToolhelp32Snapshot failed (%d)\n", GetLastError());
		return 1;
	}

	if (Heap32ListFirst(hHeapSnap, &hl))
	{
		do
		{
			HEAPENTRY32 he;
			ZeroMemory(&he, sizeof(HEAPENTRY32));
			he.dwSize = sizeof(HEAPENTRY32);

			if (Heap32First(&he, dwPID, hl.th32HeapID))
			{
				printf("\nHeap ID: %d\n", hl.th32HeapID);
				do
				{
					printf("Block size: %d\n", he.dwBlockSize);

					he.dwSize = sizeof(HEAPENTRY32);
				} while (Heap32Next(&he));
			}
			hl.dwSize = sizeof(HEAPLIST32);
		} while (Heap32ListNext(hHeapSnap, &hl));
	}
	else 
		printf("Cannot list first heap (%d)\n", GetLastError());

	CloseHandle(hHeapSnap);

	return(TRUE);
}

DWORD ListCommandLineW(HANDLE hProcess, LPWSTR pszBuffer, UINT bufferLength)
{
	struct RTL_USER_PROCESS_PARAMETERS_I
	{
		BYTE Reserved1[16];
		PVOID Reserved2[10];
		UNICODE_STRING ImagePathName;
		UNICODE_STRING CommandLine;
	};

	struct PEB_INTERNAL
	{
		BYTE Reserved1[2];
		BYTE BeingDebugged;
		BYTE Reserved2[1];
		PVOID Reserved3[2];
		struct PEB_LDR_DATA* Ldr;
		RTL_USER_PROCESS_PARAMETERS_I* ProcessParameters;
		BYTE Reserved4[104];
		PVOID Reserved5[52];
		struct PS_POST_PROCESS_INIT_ROUTINE* PostProcessInitRoutine;
		BYTE Reserved6[128];
		PVOID Reserved7[1];
		ULONG SessionId;
	};

	typedef NTSTATUS(NTAPI* NtQueryInformationProcessPtr)(
		IN HANDLE ProcessHandle,
		IN PROCESSINFOCLASS ProcessInformationClass,
		OUT PVOID ProcessInformation,
		IN ULONG ProcessInformationLength,
		OUT PULONG ReturnLength OPTIONAL);

	typedef ULONG(NTAPI* RtlNtStatusToDosErrorPtr)(NTSTATUS Status);

	// Locating functions
	HINSTANCE hNtDll = GetModuleHandleW(L"ntdll.dll");
	NtQueryInformationProcessPtr NtQueryInformationProcess = (NtQueryInformationProcessPtr)GetProcAddress(hNtDll, "NtQueryInformationProcess");
	RtlNtStatusToDosErrorPtr RtlNtStatusToDosError = (RtlNtStatusToDosErrorPtr)GetProcAddress(hNtDll, "RtlNtStatusToDosError");

	if (!NtQueryInformationProcess || !RtlNtStatusToDosError)
	{
		//printf("Functions cannot be located.\n");
		return 0;
	}

	// Get PROCESS_BASIC_INFORMATION
	PROCESS_BASIC_INFORMATION pbi;
	ULONG len;
	NTSTATUS status = NtQueryInformationProcess(
		hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &len);
	SetLastError(RtlNtStatusToDosError(status));
	if (NT_ERROR(status) || !pbi.PebBaseAddress)
	{
		//printf("\nNtQueryInformationProcess(ProcessBasicInformation) failed.\n");
		return 0;
	}

	// Read PEB memory block
	SIZE_T bytesRead = 0;
	PEB_INTERNAL peb;
	if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead))
	{
		//printf("Reading PEB failed.\n");
		return 0;
	}

	// Obtain size of commandline string
	RTL_USER_PROCESS_PARAMETERS_I upp;
	if (!ReadProcessMemory(hProcess, peb.ProcessParameters, &upp, sizeof(upp), &bytesRead))
	{
		//printf("Reading USER_PROCESS_PARAMETERS failed.\n");
		return 0;
	}

	if (!upp.CommandLine.Length)
	{
		//printf("Command line length is 0.\n");
		return 0;
	}

	// Check the buffer size
	DWORD dwNeedLength = (upp.CommandLine.Length + 1) / sizeof(wchar_t) + 1;
	if (bufferLength < dwNeedLength)
	{
		//printf("Not enough buffer.\n");
		return dwNeedLength;
	}

	// Get the actual command line
	pszBuffer[dwNeedLength - 1] = L'\0';
	if (!ReadProcessMemory(hProcess, upp.CommandLine.Buffer, pszBuffer, upp.CommandLine.Length, &bytesRead))
	{
		//printf("Reading command line failed.\n");
		return 0;
	}

	return bytesRead / sizeof(wchar_t);
}

// Simple clean up routine
void Cleanup(PTOKEN_GROUPS ptgrp)
{
	// Release the buffer for the token groups.

	if (ptgrp != NULL)
	{
		HeapFree(GetProcessHeap(), 0, (LPVOID)ptgrp);
	}
}

// Get the logon SID and convert it to SID string...
BOOL GetLogonSID(HANDLE hToken, PSID ppsid)
{
	BOOL bSuccess = FALSE;
	DWORD dwIndex;
	DWORD dwLength = 0;
	PTOKEN_GROUPS ptgrp = NULL;
	// Dummy initialization...
	LPTSTR pSid = NULL;

	

	// Verify the parameter passed in is not NULL.
	// Although we just provide an empty buffer...
	if (ppsid == NULL)
	{
		Cleanup(ptgrp);
	}
	
	// Get the required buffer size and allocate the TOKEN_GROUPS buffer.
	if (!GetTokenInformation(
		hToken,             // handle to the access token
		TokenGroups,		// get information about the token's groups
		(LPVOID)ptgrp,		// pointer to TOKEN_GROUPS buffer
		0,                  // size of buffer
		&dwLength			// receives required buffer size
		))
	{

		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		{
			Cleanup(ptgrp);
		}
		else
		{
			ptgrp = (PTOKEN_GROUPS)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwLength);
		}

		if (ptgrp == NULL)
		{
			Cleanup(ptgrp);
		}
	}
	
	// Get the token group information from the access token.
	if (!GetTokenInformation(
		hToken,         // handle to the access token
		TokenGroups,    // get information about the token's groups
		(LPVOID)ptgrp, // pointer to TOKEN_GROUPS buffer
		dwLength,       // size of buffer
		&dwLength       // receives required buffer size
		))
	{
		Cleanup(ptgrp);
		return FALSE;
	}

	// Loop through the groups to find the logon SID.
		for (dwIndex = 0; dwIndex < ptgrp->GroupCount; dwIndex++)
		{
			if ((ptgrp->Groups[dwIndex].Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID)
			{
				// If the logon SID is found then make a copy of it.
				dwLength = GetLengthSid(ptgrp->Groups[dwIndex].Sid);

				// Allocate a storage
				ppsid = (PSID)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwLength);

				// and verify again...
				if (ppsid == NULL)
					Cleanup(ptgrp);

				// If Copying the SID fails...
				if (!CopySid(dwLength,
					ppsid,    // Destination
					ptgrp->Groups[dwIndex].Sid))  // Source
				{
					HeapFree(GetProcessHeap(), 0, (LPVOID)ppsid);
					Cleanup(ptgrp);
				}


				
				// Convert the logon sid to SID string format
				if (!(ConvertSidToStringSid(
					ppsid,  // Pointer to the SID structure to be converted
					&pSid))) // Pointer to variable that receives the null-terminated SID string
				{
					Cleanup(ptgrp);
					exit(1);
				}
				else
				{
					cout << pSid;
				}
				// The search was found, so break out from the loop
				break;
			}
		}

	LocalFree(pSid);

	// If everything OK, returns a clean slate...
	bSuccess = TRUE;
	return bSuccess;
}

BOOL FreeLogonSID(PSID ppsid)
{
	HeapFree(GetProcessHeap(), 0, (LPVOID)ppsid);
	return TRUE;
}

void killProcessByName(const char *filename)
{
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
	PROCESSENTRY32 pEntry;
	pEntry.dwSize = sizeof(pEntry);
	BOOL hRes = Process32First(hSnapShot, &pEntry);
	while (hRes)
	{
		if (strcmp(pEntry.szExeFile, filename) == 0)
		{
			HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, 0,(DWORD)pEntry.th32ProcessID);
			if (hProcess != NULL)
			{
				TerminateProcess(hProcess, 9);
				CloseHandle(hProcess);
			}
		}
		hRes = Process32Next(hSnapShot, &pEntry);
	}
	CloseHandle(hSnapShot);
}

void ChangePriority(char *filename,char *priority)
{
	DWORD dwError, dwPriClass;
	int perNumber = atoi(priority);


	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			if (strcmp(entry.szExeFile, filename) == 0)
			{
				HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);

				SetPriorityClass(hProcess, perNumber);
				// Do stuff..

				CloseHandle(hProcess);
			}
		}
	}

	CloseHandle(snapshot);

}



