rule js_obfuscation : obfuscation
{
    strings:
        $hexstr = /\\x[0-9a-fA-F]{2}/
    condition:
        #hexstr > 3
}
