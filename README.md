# EnumMitigations
Reports on Driver, LSASS and other security services mitigations. I got inspired to build upon the EnumMitigations tool provided in the Evasion Lab (CETP) from [Altered Security](https://www.alteredsecurity.com/evasionlab), taught by [Saad Ahla](https://www.linkedin.com/in/saad-ahla/).

### Checks
- Driver Security Mitigations
  - Secure boot
  - Test Signing mode
  - Hypervisor-protected Code Integrity
  - Virtualization-based Security
  - Windows Defender Application Control
- LSASS mitigations
  -  CredentialGuard
  -  RunASPPL
  -  When running in elevated context it retrieves the running protection level of `lsass.exe`
- Misc
  -  System Guard Secure Launch
  -  MM Firmware Measurement
  -  Kernel-mode Hardware-enforced Stack Protection
  -  Hypervisor-Enforced Paging Translation

### Output
In my VM with nothing enabled:

```
.\EnumMitigations.exe
[i] CheckSecureBoot - Checking Secure boot
        RegOpenKeyExW - Returned handle to the key 0x000000000000005C
        RegQueryValueExW - Received 4 bytes, UEFISecureBootEnabled = 0x0
[+] CheckSecureBoot - Secure boot information retrieved
[i] CheckTestSigningModeAndDSE - Checking Signing mode
        LoadLibraryA - Received handle to ntdll.dll 0x00007FFC39360000
        GetProcAddress - Received address to NtQuerySystemInformation 0x00007FFC394C2480
        NtQuerySystemInformation - Received 8 bytes of SYSTEM_CODEINTEGRITY_INFORMATION
        NtQuerySystemInformation - SCI CodeIntegrityOptions: 0x280203
[+] CheckTestSigningModeAndDSE - Signing mode status retrieved
[i] CheckSecuritySettingsWMI - Checking security configurations via WMI
        CoInitializeSecurity - OK Set COM security levels
        CoCreateInstance - OK created IWbemLocator object 0x0000017CDABD9500
        ConnectServer - OK connected to Device Guard WMI namespace
        CoSetProxyBlanket - OK set proxy blanket
        ExecQuery - OK query executed
[+] CheckSecuritySettingsWMI - Security configurations via WMI retrieved
[i] CheckRunasPPLRegKey - Checking CheckRunasPPL RegKey regkey
        RegOpenKeyExW - Returned handle to the key 0x0000000000000250
        RegQueryValueExW - Received 4 bytes, RunAsPPL = 0x2
[+] CheckRunasPPLRegKey - RunasPPL RegKey retrieved
[i] IsProcessHighIntegrity - Checking if current process is running in High Integrity
        OpenProcessToken - Retrieved handle to token 0x0000000000000250
        GetTokenInformation1 - Retrieved 28 bytes of token information
        malloc - Allocated 28 bytes of memory at 0x0000017CDAC22210
        GetTokenInformation2 - Retrieved 28 bytes of token information at 0x0000017CDAC22210
        GetSidSubAuthority - Integrity Level: 0x3000
[+] IsProcessHighIntegrity - Process running in High Integrity
[i] EnableDebugPrivilege - Enabling SeDebugPrivilege
        OpenProcessToken - Retrieved handle to token 0x0000000000000250
        LookupPrivilegeValueW - OK
        AdjustTokenPrivileges - Privileges changed
[+] EnableDebugPrivilege - Enabled SeDebugPrivilege
[i] GetProtectionLevel - Attempting to get protection level of "lsass.exe"
        LoadLibraryA - Received handle to ntdll.dll 0x00007FFC39360000
        GetProcAddress - Received address to NtQuerySystemInformation 0x00007FFC394C2480
        GetProcAddress - Received address to NtQueryInformationProcess 0x00007FFC394C20E0
        NtQuerySystemInformation - Retrieved size in bytes for the system information: 260192
        HeapAlloc - Allocated 260192 bytes of memory at 0x0000017CDAC26F90
        NtQuerySystemInformation - Retrieved size in bytes of system information: 260192 at 0x0000017CDAC26F90
        wcscmp - Proccess lsass.exe found with PID: 1044
        OpenProcess - Opened handle 0x0000000000000250
        NtQueryInformationProcess - lsass.exe ProtectionLevel = 65
[+] GetProtectionLevel - Protection level from "lsass.exe" retrieved

[i] ReportSecurityMitigationsDriver - Driver Security Mitigations
        [VULN] UEFI Secure Boot: Disabled
        [OK] Driver Signature Enforcement (DSE): Enabled
        [VULN] Test Signing Mode: Enabled
        [VULN] Virtualization-based Security (VBS): Disabled
        [VULN] Hypervisor-protected Code Integrity (HVCI): Not configured
        [VULN] Hypervisor-protected Code Integrity (HVCI): Not running
        [OK] Windows Defender Application Control (WDAC): Enabled and Enforced

[i] ReportSecurityMitigationsLSASS - LSASS Mitigations
        [OK] CredentialGuard: Configured
        [VULN] CredentialGuard: Not running
        [OK] LSASS RunAsPPL: Configured (Value: 2 - without UEFI , Windows 11 22H2+)
        [OK] LSASS protected - Protection Level: 0x41 - Standard protected LSASS

[i] ReportSecurityMitigationsMisc - Other Security Services Mitigations
        [VULN] System Guard Secure Launch: Not configured
        [VULN] System Guard Secure Launch: Not running
        [VULN] SMM Firmware Measurement: Not configured
        [VULN] SMM Firmware Measurement: Not running
        [VULN] Kernel-mode Hardware-enforced Stack Protection: Not configured
        [VULN] Kernel-mode Hardware-enforced Stack Protection: Not running
        [VULN] Hypervisor-Enforced Paging Translation: Not configured
        [VULN] Hypervisor-Enforced Paging Translation: Not running
```

Other example:
```
.\EnumMitigations.exe
[i] CheckSecureBoot - Checking Secure boot
        RegOpenKeyExW - Returned handle to the key 0x0000000000000158
        RegQueryValueExW - Received 4 bytes, UEFISecureBootEnabled = 0x1
[+] CheckSecureBoot - Secure boot information retrieved
[i] CheckTestSigningModeAndDSE - Checking Signing mode
        LoadLibraryA - Received handle to ntdll.dll 0x00007FFFE6780000
        GetProcAddress - Received address to NtQuerySystemInformation 0x00007FFFE68E2480
        NtQuerySystemInformation - Received 8 bytes of SYSTEM_CODEINTEGRITY_INFORMATION
        NtQuerySystemInformation - SCI CodeIntegrityOptions: 0xF401
[+] CheckTestSigningModeAndDSE - Signing mode status retrieved
[i] CheckSecuritySettingsWMI - Checking security configurations via WMI
        CoInitializeSecurity - OK Set COM security levels
        CoCreateInstance - OK created IWbemLocator object 0x000001AA1821EA20
        ConnectServer - OK connected to Device Guard WMI namespace
        CoSetProxyBlanket - OK set proxy blanket
        ExecQuery - OK query executed
[+] CheckSecuritySettingsWMI - Security configurations via WMI retrieved
[i] CheckRunasPPLRegKey - Checking CheckRunasPPL RegKey regkey
        RegOpenKeyExW - Returned handle to the key 0x000000000000024C
        RegQueryValueExW - Received 4 bytes, RunAsPPL = 0x2
[+] CheckRunasPPLRegKey - RunasPPL RegKey retrieved
[i] IsProcessHighIntegrity - Checking if current process is running in High Integrity
        OpenProcessToken - Retrieved handle to token 0x000000000000024C
        GetTokenInformation1 - Retrieved 28 bytes of token information
        malloc - Allocated 28 bytes of memory at 0x000001AA18257950
        GetTokenInformation2 - Retrieved 28 bytes of token information at 0x000001AA18257950
        GetSidSubAuthority - Integrity Level: 0x3000
[+] IsProcessHighIntegrity - Process running in High Integrity
[i] EnableDebugPrivilege - Enabling SeDebugPrivilege
        OpenProcessToken - Retrieved handle to token 0x000000000000024C
        LookupPrivilegeValueW - OK
        AdjustTokenPrivileges - Privileges changed
[+] EnableDebugPrivilege - Enabled SeDebugPrivilege
[i] GetProtectionLevel - Attempting to get protection level of "lsass.exe"
        LoadLibraryA - Received handle to ntdll.dll 0x00007FFFE6780000
        GetProcAddress - Received address to NtQuerySystemInformation 0x00007FFFE68E2480
        GetProcAddress - Received address to NtQueryInformationProcess 0x00007FFFE68E20E0
        NtQuerySystemInformation - Retrieved size in bytes for the system information: 735152
        HeapAlloc - Allocated 735152 bytes of memory at 0x000001AA19CB0080
        NtQuerySystemInformation - Retrieved size in bytes of system information: 735152 at 0x000001AA19CB0080
        wcscmp - Proccess lsass.exe found with PID: 1588
        OpenProcess - Opened handle 0x00000000000001D8
        NtQueryInformationProcess - lsass.exe ProtectionLevel = 65
[+] GetProtectionLevel - Protection level from "lsass.exe" retrieved


[i] ReportSecurityMitigationsDriver - Driver Security Mitigations
        [OK] UEFI Secure Boot: Enabled
        [OK] Driver Signature Enforcement (DSE): Enabled
        [OK] Test Signing Mode: Disabled
        [OK] Virtualization-based Security (VBS): On
        [OK] Hypervisor-protected Code Integrity (HVCI): Configured
        [OK] Hypervisor-protected Code Integrity (HVCI): Running
        [OK] Windows Defender Application Control (WDAC): Enabled and Enforced

[i] ReportSecurityMitigationsLSASS - LSASS Mitigations
        [VULN] CredentialGuard: Not configured
        [VULN] CredentialGuard: Not running
        [OK] LSASS RunAsPPL: Configured (Value: 2 - without UEFI , Windows 11 22H2+)
        [OK] LSASS protected - Protection Level: 0x41 - Standard protected LSASS

[i] ReportSecurityMitigationsMisc - Other Security Services Mitigations
        [VULN] System Guard Secure Launch: Not configured
        [VULN] System Guard Secure Launch: Not running
        [VULN] SMM Firmware Measurement: Not configured
        [VULN] SMM Firmware Measurement: Not running
        [OK] Kernel-mode Hardware-enforced Stack Protection: Configured
        [OK] Kernel-mode Hardware-enforced Stack Protection: Running
        [VULN] Hypervisor-Enforced Paging Translation: Not configured
        [VULN] Hypervisor-Enforced Paging Translation: Not running
```

![image](https://github.com/user-attachments/assets/57efba1b-5bc9-475d-890e-8d3bef51a8b7)
