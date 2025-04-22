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
-  Misc
  - System Guard Secure Launch
  - SMM Firmware Measurement
  - Kernel-mode Hardware-enforced Stack Protection
  - Hypervisor-Enforced Paging Translation

### Output
In my VM with nothing enabled:

```
.\EnumMitigations.exe
[i] CheckSecureBoot - Checking Secure boot
        RegOpenKeyExW - Returned handle to the key 0x0000000000000160
        RegQueryValueExW - Received 4 bytes, UEFISecureBootEnabled = 0x0
[i] CheckTestSigningMode - Checking Signing mode
        LoadLibraryA - Received handle to ntdll.dll 0x00007FFDD1D70000
        GetProcAddress - Received address to NtQuerySystemInformation 0x00007FFDD1E0DBA0
        NtQuerySystemInformation - Received 8 bytes of SYSTEM_CODEINTEGRITY_INFORMATION
        NtQuerySystemInformation - SCI CodeIntegrityOptions: 0x203
[i] CheckSecuritySettingsWMI - Checking security configurations via WMI
        CoInitializeSecurity - OK Set COM security levels
        CoCreateInstance - OK created IWbemLocator object 0x000001CCEA72C5B0
        ConnectServer - OK connected to Device Guard WMI namespace
        CoSetProxyBlanket - OK set proxy blanket
        ExecQuery - OK query executed
[i] CheckRunasPPL - Checking CheckRunasPPL regkey
        RegOpenKeyExW - Returned handle to the key 0x00000000000001E8
        RegQueryValueExW - RunAsPPL key does not exist. Error code: 2

[i] ReportSecurityMitigationsDriver - Driver Security Mitigations
        [VULN] UEFI Secure Boot: Disabled
        [VULN] Test Signing Mode: Enabled
        [VULN] Hypervisor-protected Code Integrity (HVCI): Not configured
        [VULN] Hypervisor-protected Code Integrity (HVCI): Not running
        [VULN] Virtualization-based Security (VBS): Disabled
        [VULN] Windows Defender Application Control (WDAC): Disabled

[i] ReportSecurityMitigationsLSASS - LSASS Mitigations
        [VULN] CredentialGuard: Not configured
        [VULN] CredentialGuard: Not running
        [VULN] LSASS RunAsPPL: Not Configured

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
        RegOpenKeyExW - Returned handle to the key 0x0000000000000168
        RegQueryValueExW - Received 4 bytes, UEFISecureBootEnabled = 0x1
[i] CheckTestSigningMode - Checking Signing mode
        LoadLibraryA - Received handle to ntdll.dll 0x00007FFF832A0000
        GetProcAddress - Received address to NtQuerySystemInformation 0x00007FFF833FFEA0
        NtQuerySystemInformation - Received 8 bytes of SYSTEM_CODEINTEGRITY_INFORMATION
        NtQuerySystemInformation - SCI CodeIntegrityOptions: 0xF405
[i] CheckSecuritySettingsWMI - Checking security configurations via WMI
        CoInitializeSecurity - OK Set COM security levels
        CoCreateInstance - OK created IWbemLocator object 0x0000026985539520
        ConnectServer - OK connected to Device Guard WMI namespace
        CoSetProxyBlanket - OK set proxy blanket
        ExecQuery - OK query executed
[i] CheckRunasPPL - Checking CheckRunasPPL regkey
        RegOpenKeyExW - Returned handle to the key 0x0000000000000244
        RegQueryValueExW - Received 4 bytes, RunAsPPL = 0x2

[i] ReportSecurityMitigationsDriver - Driver Security Mitigations
        [OK] UEFI Secure Boot: Enabled
        [OK] Test Signing Mode: Disabled
        [OK] Hypervisor-protected Code Integrity (HVCI): Configured
        [OK] Hypervisor-protected Code Integrity (HVCI): Running
        [OK] Virtualization-based Security (VBS): On
        [OK] Windows Defender Application Control (WDAC): Enabled and Enforced

[i] ReportSecurityMitigationsLSASS - LSASS Mitigations
        [VULN] CredentialGuard: Not configured
        [VULN] CredentialGuard: Not running
        [OK] LSASS RunAsPPL: Configured

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

![image](https://github.com/user-attachments/assets/7254aa76-9326-413d-8fe3-9be566f4c7ca)



