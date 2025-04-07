#pragma once

#include <Windows.h>
#include <stdio.h>
#include <Wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")

// ***** STRUCTS ***** //
typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION {
	ULONG Length;
	ULONG CodeIntegrityOptions;
} SYSTEM_CODEINTEGRITY_INFORMATION, * PSYSTEM_CODEINTEGRITY_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemCodeIntegrityInformation = 103
} SYSTEM_INFORMATION_CLASS;

typedef struct _SystemSecuritySettings {
	
	// Secure boot
	BOOL bSecureBootEnabled;

	// Test signing mode
	BOOL bTestSigningModeEnable;

	// HVCI
	BOOL bHVCIConfigured;
	BOOL bHVCIRunning;

	// Credential Guard
	BOOL bCredentialGuardConfigured;
	BOOL bCredentialGuardRunning;

	// System Guard: Secure Launch
	BOOL bSystemGuardSecureLaunchConfigured;
	BOOL bSystemGuardSecureLaunchRunning;

	// SMM Firmware Measurement
	BOOL bSMMFirmwareMeasurementConfigured;
	BOOL bSMMFirmwareMeasurementRunning;

	// Kernel Mode Stack Protection
	BOOL bKernelModeStackProtectionConfigured;
	BOOL bKernelModeStackProtectionRunning;

	// Hypervisor Paging Translation
	BOOL bHypervisorPagingTranslationConfigured;
	BOOL bHypervisorPagingTranslationRunning;

	// Virtualization-based Security
	BOOL bVirtualizationBasedSecurityEnabled;
	BOOL bVirtualizationBasedSecurityAuditEnabled;

	// Windows Defender Application Control
	BOOL bWDACEnabledEnforced;
	BOOL bWDACEnabledAudit;

	// LSASS protection RunAsPPL
	BOOL bLSASSRunAsPPLEnabled;


} SystemSecuritySettings;

// ***** TYPEDEF DEFINITIONS ***** //

// Function pointer to NtQuerySystemInformation
// https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation
typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

// ***** HELPER FUNCTIONS ***** //
// Macros for printing
#define okay(msg, ...) printf("[+] "msg "\n", ##__VA_ARGS__);
#define info(msg, ...) printf("[i] "msg "\n", ##__VA_ARGS__);
#define error(msg, ...) printf("[-] "msg "\n", ##__VA_ARGS__);

#define okayW(msg, ...) wprintf(L"[+] " msg L"\n", ##__VA_ARGS__)
#define infoW(msg, ...) wprintf(L"[i] " msg L"\n", ##__VA_ARGS__)
#define errorW(msg, ...) wprintf(L"[-] " msg L"\n", ##__VA_ARGS__)

// Tabbed versions for info prints without the [i]
#define infoW_t(msg, ...) wprintf(L"\t" msg L"\n", ##__VA_ARGS__)
#define info_t(msg, ...) printf("\t"msg "\n", ##__VA_ARGS__);

// NT Macro for succes of syscalls
#define NT_SUCCESS(status)	        (((NTSTATUS)(status)) >= 0) // https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-ntstatus-values

// ***** FUNCTION PROTOTYPES ***** //
// Function prototypes are needed so each source file is aware of the function's signature 
// (name, return type, and parameters) before the compiler encounters the function call.

// For functions in 'helpers.c'
int errorWin32(const char* msg);
int errorNT(const char* msg, NTSTATUS ntstatus);