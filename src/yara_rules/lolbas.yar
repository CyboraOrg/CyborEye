rule apt_lolbas : malware apt lolbas
{
    meta:
        description = "Detects LOLBAS patterns used by APT groups"
    strings:
        $cmd = "cmd.exe /c"
        $ps = "powershell -enc"
    condition:
        all of them
}
