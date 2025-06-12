rule ransom_note : ransomware malware
{
    strings:
        $a = "YOUR FILES HAVE BEEN ENCRYPTED"
        $b = "Send 1 BTC"
    condition:
        all of them
}
