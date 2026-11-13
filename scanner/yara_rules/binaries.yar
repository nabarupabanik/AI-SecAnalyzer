rule Suspicious_Process_Injection_APIs
{
    meta:
        description = "Detects common process injection API names in binaries"
        severity = "high"
        category = "injection"
    strings:
        $a1 = "VirtualAllocEx" ascii nocase
        $a2 = "WriteProcessMemory" ascii nocase
        $a3 = "CreateRemoteThread" ascii nocase
        $a4 = "NtUnmapViewOfSection" ascii nocase
    condition:
        2 of ($a*)
}

rule Suspicious_Dropper_Download_Exec
{
    meta:
        description = "Detects likely download-and-execute behavior markers"
        severity = "high"
        category = "downloader"
    strings:
        $d1 = "URLDownloadToFile" ascii nocase
        $d2 = "WinHttpOpen" ascii nocase
        $d3 = "InternetOpen" ascii nocase
        $d4 = "powershell" ascii nocase
        $d5 = "cmd.exe" ascii nocase
    condition:
        ($d1 and 1 of ($d2,$d3)) or ($d4 and $d5)
}

rule Packed_Artifact_UPX
{
    meta:
        description = "Detects UPX packed artifact marker"
        severity = "medium"
        category = "packed"
    strings:
        $u1 = "UPX!" ascii
        $u2 = ".UPX0" ascii
        $u3 = ".UPX1" ascii
    condition:
        $u1 or (2 of ($u*))
}
