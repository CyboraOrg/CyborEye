rule suspicious_api : suspicious
{
    meta:
        author      = "Cybora"
        date        = "2025-06-12"
        description = "Detects any mention of remote thread injection APIs"
        reference   = "Internal SOP #42"
        severity    = "medium"
        tags        = "suspicious, api"
    strings:
        $a = /create\s*remote\s*thread/i
        $b = /virtual\s*alloc/i
    condition:
        any of ($a, $b)
}
