rule PowerShell_Memory_Stager
{
    meta:
        author      = "CyborEye Threat Research"
        date        = "2025-07-06"
        description = "Detects a common PowerShell download cradle pattern used for fileless malware execution. This is more specific than a simple keyword search."
        reference   = "https://attack.mitre.org/techniques/T1059/001/"
        severity    = "high"
        tactic      = "Execution"
        technique   = "T1059.001"

    strings:
        // The core components of a fileless download and execute command
        $webclient = "New-Object System.Net.WebClient" nocase
        $download = ".DownloadString" nocase
        $invoke = "IEX" nocase

    condition:
        // Require all three components to be present for a high-confidence match
        all of them
}
