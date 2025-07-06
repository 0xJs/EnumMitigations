#include "common.h"

BOOL IsProcessHighIntegrity() {

	BOOL					bSTATE				= TRUE;
	HANDLE					hToken				= NULL; // A pointer to a handle that identifies the access token
	DWORD					dwLabelSize			= NULL; // Size of the token information
	DWORD					dwLabelSize2		= NULL; // Size of the token information
	PTOKEN_MANDATORY_LABEL	pTokenLabel			= NULL; // Pointer to the TOKEN_MANDATORY_LABEL
	DWORD					dwIntegrityLevel	= NULL; // Saves the IntegrityLevel

	// Open the token of current process
	// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken
	if (!OpenProcessToken(
		NtCurrentProcess(), // Handle to current process
		TOKEN_QUERY,		// Types of access to the access token
		&hToken				// OUT Pointer to handle
	)) {
		bSTATE = FALSE;
		errorWin32("OpenProcessToken - Failed to open process token");
		goto _cleanUp;
	}
	info_t("OpenProcessToken - Retrieved handle to token 0x%p", hToken);

	// Get the size of the token information - Call should fail
	// https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation
	if (!GetTokenInformation(
		hToken,					// Handle to the token
		TokenIntegrityLevel,	// The buffer receives a TOKEN_MANDATORY_LABEL structure that specifies the token's integrity level
		NULL,					// Just getting size keep it null
		NULL,					// Just getting size keep it null
		&dwLabelSize			// Size of token information
	)) {
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
			bSTATE = FALSE;
			errorWin32("GetTokenInformation1 - Failed to get token information size");
			goto _cleanUp;
		}
	}
	info_t("GetTokenInformation1 - Retrieved %d bytes of token information", dwLabelSize);

	// Allocate buffer for token information
	pTokenLabel = (PTOKEN_MANDATORY_LABEL)malloc(dwLabelSize);
	if (!pTokenLabel) {
		bSTATE = FALSE;
		errorWin32("malloc - Failed to allocate memory");
		goto _cleanUp;
	}
	info_t("malloc - Allocated %d bytes of memory at 0x%p", dwLabelSize, pTokenLabel);

	// Get the token information
	// https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation
	if (!GetTokenInformation(
		hToken,					// Handle to the token
		TokenIntegrityLevel,	// The buffer receives a TOKEN_MANDATORY_LABEL structure that specifies the token's integrity level
		pTokenLabel,			// OUT pointer to save TOKEN_MANDATORY_LABEL structure
		dwLabelSize,			// In buffersize
		&dwLabelSize			// Size of token information
	)) {
		bSTATE = FALSE;
		errorWin32("GetTokenInformation2 - Failed to get token information");
		goto _cleanUp;
	}
	info_t("GetTokenInformation2 - Retrieved %d bytes of token information at 0x%p", dwLabelSize, pTokenLabel);

	// Extract the integrity level from the SID
	// https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-getsidsubauthoritycount
	// https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-getsidsubauthority
	DWORD dwSubAuthCount = *GetSidSubAuthorityCount(pTokenLabel->Label.Sid);
	DWORD dwSubAuth = *GetSidSubAuthority(pTokenLabel->Label.Sid, dwSubAuthCount - 1);

	dwIntegrityLevel = dwSubAuth;
	info_t("GetSidSubAuthority - Integrity Level: 0x%04x", dwIntegrityLevel);

	// Compare with high integrity SID value
	if (dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID) {

		// Return false if not high integrity level
		bSTATE = FALSE;
		goto _cleanUp;
	}

_cleanUp:

	// Close handle to token
	if (hToken) {
		CloseHandle(hToken);
	}

	// Free allocated memory
	if (pTokenLabel) {
		free(pTokenLabel);
	}

	return bSTATE;

}


BOOL EnableDebugPrivilege() {

	BOOL				bSTATE			= TRUE;
	HANDLE				hToken			= NULL;	// Stores handle to the token
	LUID				luid;					// Prepare the privilege adjustment structure
	TOKEN_PRIVILEGES	tokenPrivileges = { 0 };

	// Open the token of current process
	// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken
	if (!OpenProcessToken(
		NtCurrentProcess(),			// Handle to current process
		TOKEN_ADJUST_PRIVILEGES
		| TOKEN_QUERY,				// Types of access to the access token
		&hToken						// OUT Pointer to handle
	)) {
		bSTATE = FALSE;
		errorWin32("OpenProcessToken - Failed to open process token");
		goto _cleanUp;
	}
	info_t("OpenProcessToken - Retrieved handle to token 0x%p", hToken);

	// Look up the privilege value
	// https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupprivilegevaluea
	if (!LookupPrivilegeValueW(
		NULL,
		SE_DEBUG_NAME,
		&luid
	)) {
		bSTATE = FALSE;
		errorWin32("LookupPrivilegeValueW - Failed to locate SE_DEBUG_NAME privilege");
		goto _cleanUp;
	}
	info_t("LookupPrivilegeValueW - OK");

	// Enable the privilege
	tokenPrivileges.PrivilegeCount = 1;
	tokenPrivileges.Privileges[0].Luid = luid;
	tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	// Apply the adjusted privileges to the token
	// https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges
	if (!AdjustTokenPrivileges(
		hToken,						// Handle to token
		FALSE,						// Do not disable all privileges
		&tokenPrivileges,			// Pointer to the token privileges structure
		sizeof(TOKEN_PRIVILEGES),	// Size of the tokenPrivileges
		NULL,						// Optional can be null
		NULL						// Optional can be null
	)) {
		bSTATE = FALSE;
		errorWin32("AdjustTokenPrivileges - Failed to change privileges");
		goto _cleanUp;
	}
	info_t("AdjustTokenPrivileges - Privileges changed")

		// Check for failure to assign the privilege.
		if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
			bSTATE = FALSE;
			errorWin32("AdjustTokenPrivileges - Failed ERROR_NOT_ALL_ASSIGNED");
		}

_cleanUp:

	if (hToken) {
		CloseHandle(hToken);
	}

	return bSTATE;

}