import "pe"

rule StageHawk_Generic_PE_Suspicious_Windows_APIs
{
    meta:
        description = "PE file containing multiple suspicious Windows API names often seen in unpacking, loading, or process-manipulation workflows."
        category = "suspicious_pe_static_indicators"
        quality = "generic"
        confidence = "medium"
        false_positive_risk = "medium"
        source = "StageHawk local starter rule"
        last_updated = "2026-05-10"
    strings:
        $api01 = "VirtualAlloc" ascii wide
        $api02 = "VirtualProtect" ascii wide
        $api03 = "WriteProcessMemory" ascii wide
        $api04 = "CreateRemoteThread" ascii wide
        $api05 = "LoadLibraryA" ascii wide
        $api06 = "GetProcAddress" ascii wide
        $api07 = "WinExec" ascii wide
        $api08 = "ShellExecute" ascii wide
    condition:
        pe.is_pe and filesize < 25MB and 4 of ($api*)
}

rule StageHawk_Generic_PE_PowerShell_Download_Execution_Strings
{
    meta:
        description = "PE file containing PowerShell, download, or command-execution related strings that may support suspicious triage."
        category = "suspicious_pe_script_or_download_strings"
        quality = "generic"
        confidence = "low"
        false_positive_risk = "medium"
        source = "StageHawk local starter rule"
        last_updated = "2026-05-10"
    strings:
        $ps01 = "powershell" ascii wide nocase
        $ps02 = "-enc" ascii wide nocase
        $ps03 = "ExecutionPolicy" ascii wide nocase
        $ps04 = "DownloadString" ascii wide nocase
        $ps05 = "DownloadFile" ascii wide nocase
        $ps06 = "IEX" ascii wide
        $ps07 = "cmd.exe" ascii wide nocase
        $ps08 = "wscript.exe" ascii wide nocase
        $ps09 = "mshta.exe" ascii wide nocase
    condition:
        pe.is_pe and filesize < 25MB and 3 of ($ps*)
}

rule StageHawk_Generic_PE_Persistence_Registry_Strings
{
    meta:
        description = "PE file containing Windows registry persistence path strings. This is a generic persistence indicator, not attribution."
        category = "suspicious_pe_persistence_strings"
        quality = "generic"
        confidence = "low"
        false_positive_risk = "medium"
        source = "StageHawk local starter rule"
        last_updated = "2026-05-10"
    strings:
        $reg01 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $reg02 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide nocase
        $reg03 = "CurrentVersion\\Policies\\Explorer\\Run" ascii wide nocase
        $reg04 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion" ascii wide nocase
        $reg05 = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion" ascii wide nocase
        $reg06 = "REG ADD" ascii wide nocase
        $reg07 = "schtasks" ascii wide nocase
    condition:
        pe.is_pe and filesize < 25MB and 2 of ($reg*)
}

rule StageHawk_Generic_PE_Process_Injection_API_Names
{
    meta:
        description = "PE file containing several process or injection-related API names. Matches are heuristic and require analyst review."
        category = "suspicious_pe_process_injection_api_strings"
        quality = "generic"
        confidence = "medium"
        false_positive_risk = "medium"
        source = "StageHawk local starter rule"
        last_updated = "2026-05-10"
    strings:
        $inj01 = "OpenProcess" ascii wide
        $inj02 = "VirtualAllocEx" ascii wide
        $inj03 = "WriteProcessMemory" ascii wide
        $inj04 = "CreateRemoteThread" ascii wide
        $inj05 = "QueueUserAPC" ascii wide
        $inj06 = "SetThreadContext" ascii wide
        $inj07 = "ResumeThread" ascii wide
        $inj08 = "NtUnmapViewOfSection" ascii wide
    condition:
        pe.is_pe and filesize < 25MB and 3 of ($inj*)
}

