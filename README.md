# EnumMitigations
Tool written in `C` which reports on Driver, LSASS and other security services mitigations. I got inspired to expand upon the tool provided in the Evasion Lab (CETP) which enumerated DSE from [Altered Security](https://www.alteredsecurity.com/evasionlab), taught by [Saad Ahla](https://www.linkedin.com/in/saad-ahla/). Now including even more security settings related to drivers and lsass.

## What settings does it check
- Driver Security Mitigations
  - Secure boot
  - Test Signing mode
  - Hypervisor-protected Code Integrity
  - Virtualization-based Security
  - Windows Defender Application Control
- LSASS protections
  -  CredentialGuard
  -  RunASPPL
  -  When run with Administrator privileges, it retrieves and reports LSASS’s actual process protection level (e.g., 0x41 or 0x00)
- Misc
  -  System Guard Secure Launch
  -  MM Firmware Measurement
  -  Kernel-mode Hardware-enforced Stack Protection
  -  Hypervisor-Enforced Paging Translation
 
## How to run it
- Compile it using Visual Studio
- Run in elevated context so that the tool can enumerate the current protection level of `lsass.exe`. The tool works without it but it won't be able to retrieve the protection level.

```
.\EnumMitigations.exe
```

## Information / Notes about these protections

### Kernel Driver protections
- **Windows Hardware Quality Labs (WHQL)**
	- Since 2016, all third-party kernel-mode drivers must be submitted through WHQL to be signed by Microsoft. 
	- This process ensures drivers are validated for security and stability before being allowed on Windows.
	- WHQL signing is mandatory for drivers to be distributed through Windows Update and Microsoft Update Catalog.
	- Exception: Drivers signed before July 29, 2015 can still be loaded without re-submission, though Microsoft may block known-vulnerable ones.
	- Tools like HookSignTool have been used to re-sign drivers by hijacking legacy signatures, but this is considered a legacy bypass and may no longer be viable on modern systems (especially with HVCI or VBS enabled).
 - **Driver Signature Enforcement (DSE)**
	- A mandatory security feature since Windows Vista x64, ensuring that only signed kernel-mode drivers are loaded.
    - Enforced via the Code Integrity engine (`CI.dll`), which includes a global variable `g_CiOptions`:
	    - `0x6` – DSE Enabled (default)
	    - `0x0` – DSE Disabled
	    - `0xE` – Test Signing Mode (allows test-signed drivers)
	- Disabling DSE directly (via patching `g_CiOptions`) is protected by:
	    - PatchGuard (aka Kernel Patch Protection)
	    - HyperGuard (on supported hardware)
	    - Virtualization-Based Security (VBS) in modern Windows
	- Attempts to modify kernel memory (like `g_CiOptions`) from within drivers are blocked, making direct tampering extremely difficult or unstable.
- **Virtualization-Based Security (VBS)**
	- A platform-level security feature that uses hardware virtualization (e.g., Intel VT-x or AMD-V) to create isolated memory regions for sensitive OS components.
	- Enables features such as:
	    - Credential Guard (protects secrets like NTLM hashes and Kerberos tickets)
	    - Hypervisor-Enforced Code Integrity (HVCI)
	    - Secure Kernel Mode execution
	- When enabled, VBS isolates critical components from the rest of the OS, making kernel exploits significantly harder.
	- Many driver enforcement policies become significantly stricter when VBS is enabled.
	- Required for several enterprise-level protections and enabled by default on many newer Windows 11 systems.
	- Disabling VBS disables dependent features like HVCI and reduces overall kernel protection.
- **Hypervisor-Enforced Code Integrity (HVCI)**
	- Component of VBS that uses Hyper-V to isolate and protect kernel code integrity policies. Enabled by enabling memory integrity within Defender dashboard.
	- Prevents unsigned or improperly signed kernel-mode drivers from being loaded.
	- Requires drivers to be:
	    - Signed with EV certificates (WHQL program)
	    - HVCI-compatible (e.g., no legacy functions or unsupported calls)
	- Since Windows 11 (2022 Update), Microsoft enables the vulnerable driver blocklist by default across all devices. This blocklist:
	    - Is maintained by Microsoft and updated 1–2 times per year
	    - Blocks known vulnerable, signed drivers even if they are otherwise valid.
-  **Windows Defender Application Control (WDAC)**
	- A Windows security feature that defines what code is allowed to run, including drivers.
	- Can block both:
	    - Unsigned drivers
	    - Signed but vulnerable drivers (by using the Microsoft Recommended Driver Blocklist)
	- Enforced via:
	    - WDAC policies (enterprise-configurable)
	    - Smart App Control (consumer-focused, Windows 11)
	- WDAC may be stricter than HVCI because it allows organizations to enforce the most up-to-date blocklists, which may be newer than those bundled with HVCI.
- **Secure Boot**
	- A UEFI firmware-level security feature that ensures only trusted bootloaders and kernel-mode drivers are executed at startup.
	- Uses public key infrastructure (PKI) to validate the signatures of boot components (including early boot drivers).
	- Blocks boot-start unsigned or tampered drivers even before Windows fully loads.
	- Must be enabled in UEFI settings, and relies on OEM firmware trust chains (e.g., Microsoft’s keys)

### LSA Protection
- Adds Protection level to a process and resides in the kernel in the `Protection` field as 1 byte value in the `EPROCESS` structure. Blocks untrusted tools (e.g. Mimikatz) from reading LSASS memory.
- Configuration
	- Automatically enabled on Win11 22H2 [link](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection#automatic-enablement)
	- Can be enabled by configured the registry key `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa` to 
		- `1` - This value enables `0x41` `PS_PROTECTED_LSA_LIGHT` - with a UEFI variable,
		- `2` - This value enables `0x41` PS_PROTECTED_LSA_LIGHT - without a UEFI variable and only enforced on Windows 11 build 22H2 and later
- The following protection levels exist

| Protection Level                | Value | Signer           | Type                |
| ------------------------------- | ----- | ---------------- | ------------------- |
| PS_PROTECTED_SYSTEM             | 0x72  | WinSystem (7)    | Protected (2)       |
| PS_PROTECTED_WINTCB             | 0x62  | WinTcb (6)       | Protected (2)       |
| PS_PROTECTED_WINDOWS            | 0x52  | Windows (5)      | Protected (2)       |
| PS_PROTECTED_AUTHENTICODE       | 0x12  | Authenticode (1) | Protected (2)       |
| PS_PROTECTED_WINTCB_LIGHT       | 0x61  | WinTcb (6)       | Protected Light (1) |
| PS_PROTECTED_WINDOWS_LIGHT      | 0x51  | Windows (5)      | Protected Light (1) |
| PS_PROTECTED_LSA_LIGHT          | 0x41  | Lsa (4)          | Protected Light (1) |
| PS_PROTECTED_ANTIMALWARE_LIGHT  | 0x31  | Antimalware (3)  | Protected Light (1) |
| PS_PROTECTED_AUTHENTICODE_LIGHT | 0x11  | Authenticode (1) | Protected Light (1) |

### Credential Guard
- Isolates LSASS secrets using Virtualization-Based Security (VBS). Secrets such as NTLM-hashes and TGT's are now stored in `lsasio.exe`.
- Enabled by default in Windows 11 22H2+ and Windows Server 2025
- Requires UEFI, Secure Boot, and VBS (Virtualization-Based Security) to be active.
- On enterprise-joined or AAD-joined Windows 11 22H2+ systems, Credential Guard is **enabled by default** unless explicitly disabled.

## Example output
In my VM with nothing enabled:

```
.\EnumMitigations.exe
...snip...

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
...snip...

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
