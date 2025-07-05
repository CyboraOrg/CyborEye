rule ransom_note : ransomware malware
{
    meta:
        author      = "Cybora"
        date        = "2025-06-12"
        description = "Detects typical ransomware ransom note language"
        reference   = "https://attack.mitre.org/techniques/T1486/"
        severity    = "critical"
        tags        = "ransomware, malware, data_theft"
    strings:
        $text1 = "YOUR FILES HAVE BEEN ENCRYPTED" nocase
        $text2 = "send" nocase
        $btc   = /[0-9]+\s*BTC/i
    condition:
        all of them
}
