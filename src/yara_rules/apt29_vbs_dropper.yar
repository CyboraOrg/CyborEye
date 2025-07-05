rule APT29_VBS_Dropper
{
    meta:
        description = "Detects VBScript droppers consistent with APT29/Cozy Bear techniques, where PowerShell payloads are written to the registry."
        author = "CyborEye Threat Research"
        severity = "High"
        reference = "https://attack.mitre.org/groups/G0016/"
        tactic = "Persistence"
        technique = "T1547.001"

    strings:
        // VBScript objects used to interact with the system
        $obj1 = "WScript.Shell" wide ascii
        $obj2 = "ADODB.Stream" wide ascii
        $obj3 = "RegWrite" wide ascii

        // Specific PowerShell indicators
        $ps1 = "powershell" wide ascii
        $ps2 = "IEX" wide ascii
        $ps3 = "New-Object" wide ascii
        
        // Registry interaction
        $reg1 = "HKCU\\Software\\" wide ascii

    condition:
        // Must be a VBScript file (check for common VBS keywords)
        uint16(0) == 0x7263 or // "cr" for CreateObject
        uint16(0) == 0x6944 or // "Di" for Dim
        // High confidence: requires objects for shell and registry, plus PowerShell indicators
        (all of ($obj*) and 2 of ($ps*)) or
        // Medium confidence: requires registry writing and a specific registry path
        ($obj3 and $reg1 and 1 of ($ps*))
}