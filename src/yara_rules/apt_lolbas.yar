rule apt_lolbas : malware apt lolbas
{
    meta:
        author      = "Cybora"
        date        = "2025-06-12"
        description = "Detects LOLBAS command usage common in APT operations"
        reference   = "https://lolbas-project.github.io/"
        severity    = "high"
        tags        = "malware, apt, lolbas"
    strings:
        $cmd = "cmd.exe /c" nocase
        $ps  = "powershell -enc" nocase
    condition:
        all of them
}
