rule Anti_Analysis_VM_Detection
{
    meta:
        author      = "CyborEye Threat Research"
        date        = "2025-07-06"
        description = "Detects common strings and artifacts used by malware to identify virtual machine environments (VMWare, VirtualBox) or the presence of a debugger."
        reference   = "https://resources.infosecinstitute.com/topic/anti-reverse-engineering-anti-debugging-and-anti-virtualization-techniques/"
        severity    = "medium"
        tactic      = "Defense Evasion"
        technique   = "T1497"

    strings:
        // VMWare artifacts
        $vmware1 = "VMware" wide ascii
        $vmware2 = "vmxnet" wide ascii
        $vmware3 = "vmtoolsd" wide ascii

        // VirtualBox artifacts
        $vbox1 = "VBox" wide ascii
        $vbox2 = "virtualbox" wide ascii

        // General debugger checks
        $dbg1 = "IsDebuggerPresent" wide ascii
        $dbg2 = "OutputDebugString" wide ascii
        $dbg3 = "Sandbox" wide ascii

    condition:
        // High confidence: multiple indicators from different categories
        (1 of ($vmware*) and 1 of ($vbox*)) or
        (2 of ($vmware*) and 1 of ($dbg*)) or
        (2 of ($vbox*) and 1 of ($dbg*)) or
        // Medium confidence: strong indicators for a single VM type
        (3 of ($vmware*)) or
        (2 of ($vbox*)) or
        // Medium confidence: multiple debugger checks
        (2 of ($dbg*))
}
