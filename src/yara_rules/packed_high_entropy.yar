import "math"

rule packed_high_entropy : packer malware
{
    meta:
        author      = "Cybora"
        date        = "2025-06-12"
        description = "Detects packed/encrypted files via high overall entropy"
        reference   = "https://en.wikipedia.org/wiki/Entropy_(information_theory)"
        severity    = "high"
        tags        = "packer, malware, high_entropy"
    condition:
        filesize > 10000 and math.entropy(0, filesize) > 7.5
}
