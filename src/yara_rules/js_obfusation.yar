rule js_obfuscation : obfuscation
{
    meta:
        author      = "Cybora"
        date        = "2025-06-12"
        description = "Detects JavaScript hex-encoded strings indicating obfuscation"
        reference   = "https://owasp.org/www-community/attacks/Obfuscated_Javascript"
        severity    = "medium"
        tags        = "obfuscation, js"
    strings:
        $hexstr = /\\x[0-9A-Fa-f]{2}/
    condition:
        #hexstr > 3
}
