import "math"

rule packed_high_entropy : packer malware
{
    meta:
        description = "Detects packed files via high entropy"
    condition:
        filesize > 5000 and math.entropy(0, filesize) > 7.5
}
