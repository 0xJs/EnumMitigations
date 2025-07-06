#include "common.h"
#include <winbase.h>

// Checks if secure boot is enabled using registry (SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State\UEFISecureBootEnabled)
BOOL CheckSecureBoot(IN SystemSecuritySettings* pSettings) {

	BOOL	bSTATE = TRUE;
	HKEY	hKey = NULL;							// Stores handle to the opened registry key
	LONG	lResult = NULL;							// Stores WINAPI success value
	DWORD	dwSecureBootEnabled = NULL;							// Stores WINAPI success value
	DWORD	dwDataSize = sizeof(dwSecureBootEnabled);	// Size of the regkey value
	DWORD	dwValueType = NULL;							// Type of the regkey value

	// Open the registry key
	// https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regopenkeyexw
	lResult = RegOpenKeyExW(
		HKEY_LOCAL_MACHINE,											// Stored in HKLM
		L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",	// Subkey to be opened
		0,															// Can be null
		KEY_READ | KEY_WOW64_64KEY,									// Read the key
		&hKey														// Return handle to the key
	);
	if (lResult != ERROR_SUCCESS) {
		error("RegOpenKeyExW - Failed to open registry key. Error code: %ld", lResult);
		bSTATE = FALSE;
		goto _cleanUp;
	}
	info_t("RegOpenKeyExW - Returned handle to the key 0x%p", hKey);

	// Query the value
	// https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryvalueexw
	lResult = RegQueryValueExW(
		hKey,							// Handle to opened registry key
		L"UEFISecureBootEnabled",		// Name of registry value
		NULL,							// Reserved must be NULL
		&dwValueType,					// Pointer to a variable that receives a code indicating the type of data stored in the specified valu
		(LPBYTE)&dwSecureBootEnabled,	// Pointer to buffer which receives the value
		&dwDataSize						// Bytes received
	);
	if (lResult != ERROR_SUCCESS) {
		error("RegQueryValueExW - Failed to read UEFISecureBootEnabled registry key. Error code: %ld", lResult);
		bSTATE = FALSE;
		goto _cleanUp;
	}
	info_t("RegQueryValueExW - Received %d bytes, UEFISecureBootEnabled = 0x%X", dwDataSize, dwSecureBootEnabled);

	// Set the BOOL value
	if (dwSecureBootEnabled) {
		pSettings->bSecureBootEnabled = TRUE;
	}
	else {
		pSettings->bSecureBootEnabled = FALSE;
	}

_cleanUp:

	// Cleanup close handle
	// https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regclosekey
	if (hKey) {
		RegCloseKey(hKey);
	}

	return bSTATE;

}

// Checks if runasppl is enabled for lsass using registry (SYSTEM\\CurrentControlSet\\Control\\Lsa\RunAsPPL)
BOOL CheckRunasPPLRegKey(IN SystemSecuritySettings* pSettings) {

	BOOL	bSTATE = TRUE;
	HKEY	hKey = NULL;					// Stores handle to the opened registry key
	LONG	lResult = NULL;					// Stores WINAPI success value
	DWORD	dwRunAsPPL = NULL;					// Stores the regkey value
	DWORD	dwDataSize = sizeof(dwRunAsPPL);	// Size of the regkey value
	DWORD	dwValueType = NULL;					// Type of the regkey value

	// Open the registry key
	// https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regopenkeyexw
	lResult = RegOpenKeyExW(
		HKEY_LOCAL_MACHINE,											// Stored in HKLM
		L"SYSTEM\\CurrentControlSet\\Control\\Lsa",					// Subkey to be opened
		0,															// Can be null
		KEY_READ | KEY_WOW64_64KEY,									// Read the key
		&hKey														// Return handle to the key
	);
	if (lResult != ERROR_SUCCESS) {
		error("RegOpenKeyExW - Failed to open registry key. Error code: %ld", lResult);
		bSTATE = FALSE;
		goto _cleanUp;
	}
	info_t("RegOpenKeyExW - Returned handle to the key 0x%p", hKey);

	// Query the value
	// https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryvalueexw
	lResult = RegQueryValueExW(
		hKey,							// Handle to opened registry key
		L"RunAsPPL",					// Name of registry value
		NULL,							// Reserved must be NULL
		&dwValueType,					// Pointer to a variable that receives a code indicating the type of data stored in the specified valu
		(LPBYTE)&dwRunAsPPL,			// Pointer to buffer which receives the value
		&dwDataSize						// Bytes received
	);
	if (lResult != ERROR_SUCCESS) {
		info_t("RegQueryValueExW - RunAsPPL key does not exist. Error code: %ld", lResult);
		pSettings->bLSASSRunAsPPLEnabled = FALSE;
		goto _cleanUp;
	}
	info_t("RegQueryValueExW - Received %d bytes, RunAsPPL = 0x%X", dwDataSize, dwRunAsPPL);

	// Set the BOOL value
	if (dwRunAsPPL) {
		pSettings->bLSASSRunAsPPLEnabled = TRUE;
	}

	// Store the LSASS runasppl value
	pSettings->dwLSASSRunAsPPLValue = dwRunAsPPL;

_cleanUp:

	// Cleanup close handle
	// https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regclosekey
	if (hKey) {
		RegCloseKey(hKey);
	}

	return bSTATE;

}

// Checks if DSE and TestSigningMode is enabled or disabled
BOOL CheckTestSigningModeAndDSE(IN SystemSecuritySettings* pSettings) {

	BOOL		bSTATE = TRUE;
	HMODULE		hNTDLL = NULL; // Stores handle to ntdll.dll
	NTSTATUS	STATUS = NULL; // Stores the NTSTATUS
	ULONG		uReturn = NULL; // Size returned in bytes from NtQuerySystemInformation

	// Get handle to ntdll.dll
	// https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya
	hNTDLL = LoadLibraryA("ntdll.dll");
	if (!hNTDLL) {
		errorWin32("LoadLibraryA - Failed to get handle to ntdll.dll");
		bSTATE = FALSE;
		goto _cleanUp;
	}
	info_t("LoadLibraryA - Received handle to ntdll.dll 0x%p", hNTDLL);

	fnNtQuerySystemInformation NtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(hNTDLL, "NtQuerySystemInformation");
	if (!NtQuerySystemInformation) {
		errorWin32("GetProcAddress - Failed to address of NtQuerySystemInformation");
		bSTATE = FALSE;
		goto _cleanUp;
	}
	info_t("GetProcAddress - Received address to NtQuerySystemInformation 0x%p", NtQuerySystemInformation);

	SYSTEM_CODEINTEGRITY_INFORMATION sci = { 0 };
	sci.Length = sizeof(sci);

	// Get the SystemCodeIntegrityInformation information
	// https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation
	STATUS = NtQuerySystemInformation(
		SystemCodeIntegrityInformation, // Returns a SYSTEM_CODEINTEGRITY_INFORMATION structure that can be used to determine the options being enforced by Code Integrity on the system.
		&sci,							// Pointer to SYSTEM_CODEINTEGRITY_INFORMATION struct
		sizeof(sci),					// Size of the SYSTEM_CODEINTEGRITY_INFORMATION struct
		&uReturn						// Returned size, no need to save it
	);
	if (!NT_SUCCESS(STATUS)) {
		errorNT("NtQuerySystemInformation failed", STATUS);
		bSTATE = FALSE;
		goto _cleanUp;
	}
	info_t("NtQuerySystemInformation - Received %lu bytes of SYSTEM_CODEINTEGRITY_INFORMATION", uReturn);
	info_t("NtQuerySystemInformation - SCI CodeIntegrityOptions: 0x%X", sci.CodeIntegrityOptions);

	// Check for Driver Signature Enforcement (DSE) being enabled
	if (sci.CodeIntegrityOptions & 0x01) { // CODEINTEGRITY_OPTION_ENABLED
		pSettings->bDSEEnabled = TRUE;
	}
	else {
		pSettings->bDSEEnabled = FALSE;
	}

	// Check for Test-Signing mode
	if (sci.CodeIntegrityOptions & 0x02) { // CODEINTEGRITY_OPTION_TESTSIGN
		pSettings->bTestSigningModeEnabled = TRUE;
	}
	else {
		pSettings->bTestSigningModeEnabled = FALSE;
	}

_cleanUp:

	// Cleanup close handle
	if (hNTDLL) {
		FreeLibrary(hNTDLL);
	}

	return bSTATE;
}

// Check various security settings through WMI
BOOL CheckSecuritySettingsWMI(IN SystemSecuritySettings* pSettings) {

	BOOL					bSTATE = TRUE; // Stores the status of function
	HRESULT					hres = NULL; // Result status for COM and WMI operations
	IWbemLocator* pLoc = NULL; // Pointer to IWbemLocator interface used to connect to WMI
	IWbemServices* pSvc = NULL; // Pointer to IWbemServices interface for executing WMI queries
	IEnumWbemClassObject* pEnumerator = NULL; // Pointer to enumerator for WMI query results
	IWbemClassObject* pclsObj = NULL; // Pointer to current WMI class object in enumeration
	ULONG					uReturn = 0;	// Stores number of WMI objects returned in enumeration
	IWbemServices* pSecureBootSvc = NULL; // [Unused] Intended pointer to SecureBoot WMI service interface
	BSTR					namespacePath = NULL; // WMI namespace path string
	BSTR					querylanguagestring = NULL; // WQL language identifier string
	BSTR					querystring = NULL; // WQL query string

	// Initializes the COM library for use by the calling thread
	// https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-coinitializeex
	hres = CoInitializeEx(
		NULL,					// Reserved must be NULL
		COINIT_MULTITHREADED	// Set the default COINIT_MULTITHREADED
	);
	if (FAILED(hres)) {
		// Print error in uppercase decimal
		error("CoInitializeEx - Failed to initialize COM library - error = 0x%X", hres);
		bSTATE = FALSE;
		goto _cleanUp;
	}
	//info_t("CoInitializeEx - Initialized COM Library - success");

	// Set COM security levels for proper communication
	// https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-coinitializesecurity
	hres = CoInitializeSecurity(
		NULL,							// Can be NULL
		-1,								// A value of -1 tells COM to choose which authentication services to register
		NULL,							// Must be Null when cAuthSvc = -1
		NULL,							// Reserved must be NULL
		RPC_C_AUTHN_LEVEL_DEFAULT,		// The default authentication level for the process. Both servers and clients use this parameter when they call CoInitializeSecurity.
		RPC_C_IMP_LEVEL_IMPERSONATE,	// The server process can impersonate the client's security context while acting on behalf of the client.
		NULL,							// Can be NULL
		EOAC_NONE,						// Indicates that no capability flags are set.
		NULL							// Reserved must be NULL
	);
	if (FAILED(hres)) {
		error("CoInitializeSecurity - Failed to initialize security - error = 0x%X", hres);

		bSTATE = FALSE;
		goto _cleanUp;
	}
	info_t("CoInitializeSecurity - OK Set COM security levels");

	// Obtain the initial WMI locator object
	// https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cocreateinstance
	hres = CoCreateInstance(
		&CLSID_WbemLocator,		// The CLSID associated with the data and code that will be used to create the object.
		0,						// indicates that the object is not being created as part of an aggregate.
		CLSCTX_INPROC_SERVER,	// Context in which the code that manages the newly created object will run
		&IID_IWbemLocator,		// A reference to the identifier of the interface to be used to communicate with the object.
		(LPVOID*)&pLoc			// Address of pointer variable that receives the interface pointer requested in riid.
	);
	if (FAILED(hres)) {
		error("CoCreateInstance - Failed to create IWbemLocator object - error = 0x%X", hres);
		bSTATE = FALSE;
		goto _cleanUp;
	}
	info_t("CoCreateInstance - OK created IWbemLocator object 0x%p", pLoc);

	// Conect to the device guard namespace in WMI
	// https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemlocator-connectserver
	namespacePath = SysAllocString(L"ROOT\\Microsoft\\Windows\\DeviceGuard");
	hres = pLoc->lpVtbl->ConnectServer(
		pLoc,
		namespacePath,
		NULL,	// No username
		NULL,	// No password
		NULL,	// No Locale
		0,		// No Security flags
		NULL,	// No authority
		NULL,	// No context object
		&pSvc	// Pointer to IWbemServices
	);
	if (FAILED(hres)) {
		error("ConnectServer - Could not connect to Device Guard WMI namespace - error = 0x%X", hres);
		bSTATE = FALSE;
		goto _cleanUp;
	}
	info_t("ConnectServer - OK connected to Device Guard WMI namespace");

	// Set security levels for the proxy connection to WMI to ensure proper authentication
	// https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cosetproxyblanket
	hres = CoSetProxyBlanket(
		pSvc,                        // Pointer to the proxy to be set
		RPC_C_AUTHN_WINNT,           // Use Windows NT authentication
		RPC_C_AUTHZ_NONE,            // No specific authorization service is required.
		NULL,                        // Not required
		RPC_C_AUTHN_LEVEL_CALL,      // Authenticates only at the beginning of each remote procedure call when the server receives the request
		RPC_C_IMP_LEVEL_IMPERSONATE, // The server process can impersonate the client's security context while acting on behalf of the client
		NULL,                        // Optional can be NULL
		EOAC_NONE                    // No specific flags are set here.
	);
	if (FAILED(hres)) {
		error("CoSetProxyBlanket - Could not set proxy blanket - error = 0x%X", hres);
		bSTATE = FALSE;
		goto _cleanUp;
	}
	info_t("CoSetProxyBlanket - OK set proxy blanket");

	// Execute the WQL query to retrieve HVCI and VBS status
	// https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-execquery
	querylanguagestring = SysAllocString(L"WQL");
	querystring = SysAllocString(L"SELECT SecurityServicesConfigured, SecurityServicesRunning, VirtualizationBasedSecurityStatus, CodeIntegrityPolicyEnforcementStatus FROM Win32_DeviceGuard");
	hres = pSvc->lpVtbl->ExecQuery(
		pSvc,							// Pointer to the IWbemServices interface
		querylanguagestring,			// specifying the query language
		querystring,					// Query to execute
		WBEM_FLAG_FORWARD_ONLY |		// Flag to indicate the results should be enumerated only in a forward direction.
		WBEM_FLAG_RETURN_IMMEDIATELY,	// Flag indicating the query should return immediately, even if the result set is not yet fully populated.
		NULL,							// Reserved NULL
		&pEnumerator					// Pointer to an IWbemObjectAccess enumerator, which will be filled with results of the query.
	);
	if (FAILED(hres)) {
		error("ExecQuery - Query failed - error = 0x%X", hres);
		bSTATE = FALSE;
		goto _cleanUp;
	}
	info_t("ExecQuery - OK query executed");

	// Process the results of the query
	while (pEnumerator) {
		// https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-ienumwbemclassobject-next
		HRESULT hres2 = pEnumerator->lpVtbl->Next(
			pEnumerator,     // Pointer to an IWbemObjectAccess enumerator, which hold the results
			WBEM_INFINITE,   // It will wait as long as necessary to retrieve the object.
			1,               // Retrieve 1 object
			&pclsObj,        // Pointer to where the retrieved object will be stored.
			&uReturn         // Store number of retrieved objects
		);

		// If uReturn is 0 then no more objects so break
		if (uReturn == 0) {
			break;
		}

		// Save properties of the WMI object
		VARIANT vtProp;

		/// *** SECURITY SERVICES CONFIGURED & RUNNING *** //
		// https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity?tabs=security#use-win32_deviceguard-wmi-class

		// Extract the SecurityServicesConfigured property (HVCI status)
		hres2 = pclsObj->lpVtbl->Get(
			pclsObj,                        // Pointer to the object
			L"SecurityServicesConfigured",   // Property name to retrieve
			0,                               // Index of the property to retrieve
			&vtProp,                         // Variable to store the property value
			0,                               // Reserved 
			0                                // Reserved
		);
		if (FAILED(hres2)) {
			error("pclsObj->lpVtbl->Get - Failed to retrieve SecurityServicesConfigured property");
			VariantClear(&vtProp);
			pclsObj->lpVtbl->Release(pclsObj);
			continue;  // Skip to the next iteration of the loop
		}

		// Check if property is array of integers
		if (vtProp.vt == (VT_ARRAY | VT_I4)) {
			SAFEARRAY* psa = vtProp.parray;
			long lLower;
			long lUpper;
			SafeArrayGetLBound(psa, 1, &lLower);
			SafeArrayGetUBound(psa, 1, &lUpper);

			// Check each element in the array
			for (long i = lLower; i <= lUpper; i++) {
				long lValue;
				if (SUCCEEDED(SafeArrayGetElement(psa, &i, &lValue))) {
					// Check for Credential Guard (value 1)
					if (lValue == 1) {
						pSettings->bCredentialGuardConfigured = TRUE;
					}
					// Check for HVCI (value 2)
					else if (lValue == 2) {
						pSettings->bHVCIConfigured = TRUE;
					}
					// Check for System Guard Secure Launch (value 3)
					else if (lValue == 3) {
						pSettings->bSystemGuardSecureLaunchConfigured = TRUE;
					}
					// Check for SMM Firmware Measurement (value 4)
					else if (lValue == 4) {
						pSettings->bSMMFirmwareMeasurementConfigured = TRUE;
					}
					// Check for Kernel-mode Stack Protection (value 5)
					else if (lValue == 5) {
						pSettings->bKernelModeStackProtectionConfigured = TRUE;
					}
					// Check for Hypervisor Paging Translation (value 7)
					else if (lValue == 7) {
						pSettings->bHypervisorPagingTranslationConfigured = TRUE;
					}
				}
			}
		}
		// https://learn.microsoft.com/en-us/windows/win32/api/oleauto/nf-oleauto-variantclear
		VariantClear(&vtProp);

		// Extract the SecurityServicesRunning property (HVCI status)
		hres2 = pclsObj->lpVtbl->Get(
			pclsObj,                        // Pointer to the object
			L"SecurityServicesRunning",      // Property name to retrieve
			0,                               // Index of the property to retrieve
			&vtProp,                         // Variable to store the property value
			0,                               // Reserved 
			0                                // Reserved
		);
		if (FAILED(hres2)) {
			error("pclsObj->lpVtbl->Get - Failed to retrieve SecurityServicesRunning property");
			VariantClear(&vtProp);
			pclsObj->lpVtbl->Release(pclsObj);
			continue;  // Skip to the next iteration of the loop
		}

		// Check if property is array of integers
		if (vtProp.vt == (VT_ARRAY | VT_I4)) {
			SAFEARRAY* psa = vtProp.parray;
			long lLower;
			long lUpper;
			SafeArrayGetLBound(psa, 1, &lLower);
			SafeArrayGetUBound(psa, 1, &lUpper);

			// Check each element in the array
			for (long i = lLower; i <= lUpper; i++) {
				long lValue;
				if (SUCCEEDED(SafeArrayGetElement(psa, &i, &lValue))) {
					// Check for Credential Guard (value 1)
					if (lValue == 1) {
						pSettings->bCredentialGuardRunning = TRUE;
					}
					// Check for HVCI (value 2)
					else if (lValue == 2) {
						pSettings->bHVCIRunning = TRUE;
					}
					else // Check for System Guard Secure Launch (value 3)
						if (lValue == 3) {
							pSettings->bSystemGuardSecureLaunchRunning = TRUE;
						}
					// Check for SMM Firmware Measurement (value 4)
						else if (lValue == 4) {
							pSettings->bSMMFirmwareMeasurementRunning = TRUE;
						}
					// Check for Kernel-mode Stack Protection (value 5)
						else if (lValue == 5) {
							pSettings->bKernelModeStackProtectionRunning = TRUE;
						}
					// Check for Hypervisor Paging Translation (value 7)
						else if (lValue == 7) {
							pSettings->bHypervisorPagingTranslationRunning = TRUE;
						}
				}
			}
		}
		// https://learn.microsoft.com/en-us/windows/win32/api/oleauto/nf-oleauto-variantclear
		VariantClear(&vtProp);

		/// *** VirtualizationBasedSecurityStatus *** //

		// Extract VirtualizationBasedSecurityStatus property (VBS status)
		hres2 = pclsObj->lpVtbl->Get(
			pclsObj,								// Pointer to the object
			L"VirtualizationBasedSecurityStatus",	// Property name to retrieve
			0,										// Index of the property to retrieve
			&vtProp,								// Variable to store the property value
			0,										// Reserved 
			0										// Reserved 
		);
		if (FAILED(hres2)) {
			error("pclsObj->lpVtbl->Get - Failed to retrieve VirtualizationBasedSecurityStatus property.");
			VariantClear(&vtProp);
			pclsObj->lpVtbl->Release(pclsObj);
			continue;  // Skip to the next iteration of the loop
		}

		// Check if value is an integer
		if (vtProp.vt == VT_I4) {
			if (vtProp.intVal == 2) {
				pSettings->bVirtualizationBasedSecurityEnabled = TRUE;
			}
			else if (vtProp.intVal == 1) {
				pSettings->bVirtualizationBasedSecurityAuditEnabled = TRUE;
			}
			else {
				pSettings->bVirtualizationBasedSecurityEnabled = FALSE;
			}
		}
		// https://learn.microsoft.com/en-us/windows/win32/api/oleauto/nf-oleauto-variantclear
		VariantClear(&vtProp);

		/// *** WINDOWS DEVICE GUARD *** //
		// Extract the CodeIntegrityPolicyEnforcementStatus property (WDAC status)
		hres2 = pclsObj->lpVtbl->Get(
			pclsObj,									// Pointer to the object
			L"CodeIntegrityPolicyEnforcementStatus",	// Property name to retrieve
			0,											// Index of the property to retrieve
			&vtProp,									// Variable to store the property value
			0,											// Reserved 
			0											// Reserved
		);
		if (FAILED(hres2)) {
			error("pclsObj->lpVtbl->Get - Failed to retrieve CodeIntegrityPolicyEnforcementStatus property");
			VariantClear(&vtProp);
			pclsObj->lpVtbl->Release(pclsObj);
			continue;  // Skip to the next iteration of the loop
		}

		// Check if the property is an integer and if WDAC is enabled and enforced (value == 2)
		if (vtProp.vt == VT_I4) {
			if (vtProp.intVal == 2) {
				pSettings->bWDACEnabledEnforced = TRUE;
			}
			else if (vtProp.intVal == 1) {
				pSettings->bWDACEnabledAudit = TRUE;
			}
			else {
				pSettings->bWDACEnabledEnforced = FALSE;
			}
		}

		// Cleanup release the current WMI Object
		pclsObj->lpVtbl->Release(pclsObj);
	}

_cleanUp:

	// Cleanup free strings
	if (namespacePath) {
		SysFreeString(namespacePath);
	}

	if (querystring) {
		SysFreeString(querystring);
	}

	if (querylanguagestring) {
		SysFreeString(querylanguagestring);
	}

	// Cleanup release
	if (pSvc) {
		pSvc->lpVtbl->Release(pSvc);
	}
	if (pLoc) {
		pLoc->lpVtbl->Release(pLoc);
	}
	if (pEnumerator) {
		pEnumerator->lpVtbl->Release(pEnumerator);
	}
	CoUninitialize();

	return bSTATE;

}

// Function which calls all the other functions
BOOL GatherSecuritySettings(IN SystemSecuritySettings* pSettings) {

	info("CheckSecureBoot - Checking Secure boot");
	if (!CheckSecureBoot(pSettings)) {
		error("CheckSecureBoot - Failed")
	}
	okay("CheckSecureBoot - Secure boot information retrieved");

	info("CheckTestSigningModeAndDSE - Checking Signing mode");
	if (!CheckTestSigningModeAndDSE(pSettings)) {
		error("CheckTestSigningModeAndDSE - Failed")
	}
	okay("CheckTestSigningModeAndDSE - Signing mode status retrieved");

	info("CheckSecuritySettingsWMI - Checking security configurations via WMI");
	if (!CheckSecuritySettingsWMI(pSettings)) {
		error("CheckSecuritySettingsWMI - Failed");
	}
	okay("CheckSecuritySettingsWMI - Security configurations via WMI retrieved");

	info("CheckRunasPPLRegKey - Checking CheckRunasPPL RegKey regkey");
	if (!CheckRunasPPLRegKey(pSettings)) {
		error("CheckRunasPPLRegKey - Failed");
	}
	okay("CheckRunasPPLRegKey - RunasPPL RegKey retrieved");

	// Check if the process is running with elevated privileges
	info("IsProcessHighIntegrity - Checking if current process is running in High Integrity");
	if (IsProcessHighIntegrity()) {
		okay("IsProcessHighIntegrity - Process running in High Integrity");

		// Enable SeDebugPrivilege to access protected processes
		info("EnableDebugPrivilege - Enabling SeDebugPrivilege");
		if (!EnableDebugPrivilege()) {
			error("EnableDebugPrivilege - Failed to enable SeDebugPrivilege");
		}
		else {
			okay("EnableDebugPrivilege - Enabled SeDebugPrivilege");

			// Get protection level of lsass.exe
			info("GetProtectionLevel - Attempting to get protection level of \"lsass.exe\"");
			if (!GetProtectionLevel(pSettings, L"lsass.exe")) {
				error("GetProtectionLevel - Failed");
			}
			okay("GetProtectionLevel - Protection level from \"lsass.exe\" retrieved");
		}
	}
	else {
		error("IsProcessHighIntegrity - Not running elevated, cannot retrieve lsass.exe protection level");
	}

	return TRUE;

}

// Function to print status of all the driver related security settings 
BOOL ReportSecurityMitigationsDriver(SystemSecuritySettings* pSettings) {

	if (pSettings->bSecureBootEnabled) {
		info_t("[OK] UEFI Secure Boot: Enabled");
	}
	else {
		info_t("[VULN] UEFI Secure Boot: Disabled");
	}

	if (pSettings->bDSEEnabled) {
		info_t("[OK] Driver Signature Enforcement (DSE): Enabled");
	}
	else {
		info_t("[VULN] Driver Signature Enforcement (DSE): Disabled");
	}

	if (pSettings->bTestSigningModeEnabled) {
		info_t("[VULN] Test Signing Mode: Enabled");
	}
	else {
		info_t("[OK] Test Signing Mode: Disabled");
	}

	if (pSettings->bVirtualizationBasedSecurityEnabled) {
		info_t("[OK] Virtualization-based Security (VBS): On");
	}
	else if (pSettings->bVirtualizationBasedSecurityAuditEnabled) {
		info_t("[ ] Virtualization-based Security (VBS): Audit");
	}
	else {
		info_t("[VULN] Virtualization-based Security (VBS): Disabled");
	}

	if (pSettings->bHVCIConfigured) {
		info_t("[OK] Hypervisor-protected Code Integrity (HVCI): Configured");
	}
	else {
		info_t("[VULN] Hypervisor-protected Code Integrity (HVCI): Not configured");
	}

	if (pSettings->bHVCIRunning) {
		info_t("[OK] Hypervisor-protected Code Integrity (HVCI): Running");
	}
	else {
		info_t("[VULN] Hypervisor-protected Code Integrity (HVCI): Not running");
	}

	if (pSettings->bWDACEnabledEnforced) {
		info_t("[OK] Windows Defender Application Control (WDAC): Enabled and Enforced");
	}
	else if (pSettings->bWDACEnabledAudit) {
		info_t("[VULN] Windows Defender Application Control (WDAC): Enabled but Not Enforced");
	}
	else {
		info_t("[VULN] Windows Defender Application Control (WDAC): Disabled");
	}

	return TRUE;

}

// Function to print status of all the lsass related security settings 
BOOL ReportSecurityMitigationsLSASS(SystemSecuritySettings* pSettings) {

	if (pSettings->bCredentialGuardConfigured) {
		info_t("[OK] CredentialGuard: Configured");
	}
	else {
		info_t("[VULN] CredentialGuard: Not configured");
	}

	if (pSettings->bCredentialGuardRunning) {
		info_t("[OK] CredentialGuard: Running");
	}
	else {
		info_t("[VULN] CredentialGuard: Not running");
	}

	if (pSettings->bLSASSRunAsPPLEnabled) {
		if (pSettings->dwLSASSRunAsPPLValue == 1) {
			info_t("[OK] LSASS RunAsPPL: Configured (Value: 1 - UEFI enforced)");
		}
		else if (pSettings->dwLSASSRunAsPPLValue == 2) {
			info_t("[OK] LSASS RunAsPPL: Configured (Value: 2 - without UEFI , Windows 11 22H2+)");
		}
		else {
			info_t("[OK] LSASS RunAsPPL: Configured (Value: %lu - Unknown or undocumented)", pSettings->dwLSASSRunAsPPLValue);
		}
	}
	else {
		info_t("[VULN] LSASS RunAsPPL: Not Configured");
	}

	if (pSettings->bLSASSProtectionLevelRetrieved == TRUE) {
		if (pSettings->ulLSASSProtectionLevel != 0) {
			if (pSettings->ulLSASSProtectionLevel == 0x41) {
				info_t("[OK] LSASS protected - Protection Level: 0x%lX - Standard protected LSASS", pSettings->ulLSASSProtectionLevel, pSettings->ulLSASSProtectionLevel);
			}
			else {
				info_t("[OK] LSASS protected - Protection Level: 0x%lX - Unknown", pSettings->ulLSASSProtectionLevel, pSettings->ulLSASSProtectionLevel);
			}
		}
		else {
			info_t("[VULN] LSASS not protected - Protection Level: %lu (0x%lX)", pSettings->ulLSASSProtectionLevel, pSettings->ulLSASSProtectionLevel);
		}
	}
	else {
		info_t("[ ] Not running in elevated context, cannot retrieve lsass.exe protection level");
	}

	return TRUE;

}

// Function to print status of all the misc related security settings 
BOOL ReportSecurityMitigationsMisc(SystemSecuritySettings* pSettings) {

	if (pSettings->bSystemGuardSecureLaunchConfigured) {
		info_t("[OK] System Guard Secure Launch: Configured");
	}
	else {
		info_t("[VULN] System Guard Secure Launch: Not configured");
	}

	if (pSettings->bSystemGuardSecureLaunchRunning) {
		info_t("[OK] System Guard Secure Launch: Running");
	}
	else {
		info_t("[VULN] System Guard Secure Launch: Not running");
	}

	if (pSettings->bSMMFirmwareMeasurementConfigured) {
		info_t("[OK] SMM Firmware Measurement: Configured");
	}
	else {
		info_t("[VULN] SMM Firmware Measurement: Not configured");
	}

	if (pSettings->bSMMFirmwareMeasurementRunning) {
		info_t("[OK] SMM Firmware Measurement: Running");
	}
	else {
		info_t("[VULN] SMM Firmware Measurement: Not running");
	}

	if (pSettings->bKernelModeStackProtectionConfigured) {
		info_t("[OK] Kernel-mode Hardware-enforced Stack Protection: Configured");
	}
	else {
		info_t("[VULN] Kernel-mode Hardware-enforced Stack Protection: Not configured");
	}

	if (pSettings->bKernelModeStackProtectionRunning) {
		info_t("[OK] Kernel-mode Hardware-enforced Stack Protection: Running");
	}
	else {
		info_t("[VULN] Kernel-mode Hardware-enforced Stack Protection: Not running");
	}

	if (pSettings->bHypervisorPagingTranslationConfigured) {
		info_t("[OK] Hypervisor-Enforced Paging Translation: Configured");
	}
	else {
		info_t("[VULN] Hypervisor-Enforced Paging Translation: Not configured");
	}

	if (pSettings->bHypervisorPagingTranslationRunning) {
		info_t("[OK] Hypervisor-Enforced Paging Translation: Running");
	}
	else {
		info_t("[VULN] Hypervisor-Enforced Paging Translation: Not running");
	}

	return TRUE;

}

// Function which calls all the Reporting functions
BOOL ReportSecurityMitigations(SystemSecuritySettings* pSettings) {

	printf("\n");
	info("ReportSecurityMitigationsDriver - Driver Security Mitigations");
	ReportSecurityMitigationsDriver(pSettings);
	printf("\n");

	info("ReportSecurityMitigationsLSASS - LSASS Mitigations");
	ReportSecurityMitigationsLSASS(pSettings);
	printf("\n");

	info("ReportSecurityMitigationsMisc - Other Security Services Mitigations");
	ReportSecurityMitigationsMisc(pSettings);
	printf("\n");

	return TRUE;

}