#include "common.h"

#define ProcessProtectionInformation 0x3D // Undocumented, used internally

// Retrieves ProtectionLevel of targets processes
BOOL GetProtectionLevel(IN SystemSecuritySettings* pSettings, IN LPCWSTR szTargetProcName) {

	BOOL							bSTATE				= TRUE;
	HMODULE							hNTDLL				= NULL;		// Stores handle to ntdll.dll
	NTSTATUS						STATUS				= NULL;		// Store NTSTATUS value
	HANDLE							hGetProcessHeap		= NULL;		// Handle to process heap
	ULONG							uReturnLen1			= NULL;		// Stores the size of system information 1st NtQuerySystemInformation call
	ULONG							uReturnLen2			= NULL;		// Stores size of system information 2nd NtQuerySystemInformation call
	PSYSTEM_PROCESS_INFORMATION		SystemProcInfo		= NULL;		// A pointer to memoery which receives the requested information. 
	PVOID							pValueToFree		= NULL;		// Save initial value of SystemProcInfo to free later
	HANDLE							hProcess			= NULL;		// Stores handle to the target process
	PROCESS_PROTECTION_INFORMATION	ppi					= { 0 };	// Holds protection info

	// Get handle to ntdll.dll
	// https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya
	hNTDLL = LoadLibraryA("ntdll.dll");
	if (!hNTDLL) {
		errorWin32("LoadLibraryA - Failed to get handle to ntdll.dll");
		bSTATE = FALSE;
		goto _cleanUp;
	}
	info_t("LoadLibraryA - Received handle to ntdll.dll 0x%p", hNTDLL);

	// Resolve address of NtQuerySystemInformation
	fnNtQuerySystemInformation pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(hNTDLL, "NtQuerySystemInformation");
	if (!pNtQuerySystemInformation) {
		errorWin32("GetProcAddress - Failed to address of NtQuerySystemInformation");
		bSTATE = FALSE;
		goto _cleanUp;
	}
	info_t("GetProcAddress - Received address to NtQuerySystemInformation 0x%p", pNtQuerySystemInformation);

	// Resolve address of NtQueryInformationProcess
	fnNtQueryInformationProcess pNtQueryInformationProcess = (fnNtQueryInformationProcess)GetProcAddress(hNTDLL, "NtQueryInformationProcess");
	if (!pNtQueryInformationProcess) {
		errorWin32("GetProcAddress - Failed to address of NtQueryInformationProcess");
		bSTATE = FALSE;
		goto _cleanUp;
	}
	info_t("GetProcAddress - Received address to NtQueryInformationProcess 0x%p", pNtQueryInformationProcess);

	// https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation
	// First NtQuerySystemInformation call, which fails but will save the 
	// This will fail with STATUS_INFO_LENGTH_MISMATCH
	// But it will provide information about how much memory to allocate (uReturnLen1)
	pNtQuerySystemInformation(
		SystemProcessInformation,	// Returns an array of SYSTEM_PROCESS_INFORMATION structures, one for each process running in the system.
		NULL,						// Can be null the first time calling
		NULL,						// Can be null the first time calling
		&uReturnLen1				// Save the size of the system information
	);
	info_t("NtQuerySystemInformation - Retrieved size in bytes for the system information: %d", uReturnLen1);

	// Get handle to process heap
	hGetProcessHeap = GetProcessHeap();

	// Allocating enough buffer for the returned array of SYSTEM_PROCESS_INFORMATION struct
	SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(hGetProcessHeap, HEAP_ZERO_MEMORY, (SIZE_T)uReturnLen1);
	if (SystemProcInfo == NULL) {
		errorWin32("HeapAlloc - failed to allocate memory");
		bSTATE = FALSE;
		goto _cleanUp;
	}
	info_t("HeapAlloc - Allocated %d bytes of memory at 0x%p", uReturnLen1, SystemProcInfo);

	// As 'SystemProcInfo' will be modified, save the initial value
	pValueToFree = SystemProcInfo;

	// Second NtQuerySystemInformation call
	// Calling NtQuerySystemInformation with the correct arguments, the output will be saved to 'SystemProcInfo'
	STATUS = pNtQuerySystemInformation(
		SystemProcessInformation,	// Returns an array of SYSTEM_PROCESS_INFORMATION structures, one for each process running in the system.
		SystemProcInfo,				// A pointer to a buffer that receives the requested information. 
		uReturnLen1,				// Size of the buffer pointed to by the SystemInformation parameter, in bytes.
		&uReturnLen2				// Size returned
	);
	if (!NT_SUCCESS(STATUS)) {
		errorNT("NtQuerySystemInformation failed", STATUS);
		bSTATE = FALSE;
		goto _cleanUp;
	}
	info_t("NtQuerySystemInformation - Retrieved size in bytes of system information: %d at 0x%p", uReturnLen2, SystemProcInfo);

	while (TRUE) {

		//infoW_t(L"Enumerated process \"%s\" - Of PID: %d", SystemProcInfo->ImageName.Buffer, SystemProcInfo->UniqueProcessId);

		// Check the process's name size
		// Comparing the enumerated process name to the intended target process
		if (SystemProcInfo->ImageName.Length && wcscmp(SystemProcInfo->ImageName.Buffer, szTargetProcName) == 0) {

			infoW_t(L"wcscmp - Proccess %s found with PID: %d", szTargetProcName, (DWORD)SystemProcInfo->UniqueProcessId);

			// Get handle to process
			// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
			hProcess = OpenProcess(
				PROCESS_QUERY_LIMITED_INFORMATION,			// Open process with these permissions only
				FALSE,										// Don't inherit handle
				(DWORD)SystemProcInfo->UniqueProcessId		// Process ID
			);
			if (hProcess == NULL) {
				errorWin32("OpenProcess - Failed to open process");
				bSTATE = FALSE;
				goto _cleanUp;
			}
			info_t("OpenProcess - Opened handle 0x%p", hProcess);

			// Call NtQueryInformationProcess to get protection level
			STATUS = pNtQueryInformationProcess(
				hProcess,
				(PROCESSINFOCLASS)ProcessProtectionInformation,
				&ppi,
				sizeof(ppi),
				&uReturnLen1
			);
			if (!NT_SUCCESS(STATUS)) {
				errorNT("NtQueryInformationProcess - Failed to get protection level", STATUS);
				bSTATE = FALSE;
				goto _cleanUp;
			}
			info_t("NtQueryInformationProcess - lsass.exe ProtectionLevel = %lu", ppi.ProtectionLevel);

			// Set the Protection level within the global struct
			pSettings->ulLSASSProtectionLevel = ppi.ProtectionLevel;
			pSettings->bLSASSProtectionLevelRetrieved = TRUE;

			break;
		}

		// if NextEntryOffset is 0, we reached the end of the array
		if (!SystemProcInfo->NextEntryOffset) {

			//info_t("Reached end of SystemProcInfo array");

			break;
		}

		// From Docs: The start of the next item in the array is the address of the previous item plus the value in the NextEntryOffset member. 
		SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);
	}

_cleanUp:

	// Free the initial address
	if (pValueToFree) {
		HeapFree(hGetProcessHeap, 0, pValueToFree);
	}

	return bSTATE;
}