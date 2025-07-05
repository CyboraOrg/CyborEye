rule Webshell_China_Chopper
{
    meta:
        author      = "CyborEye Threat Research"
        date        = "2025-07-06"
        description = "Detects the classic one-line China Chopper web shell in various web file formats."
        reference   = "https://attack.mitre.org/software/S0020/"
        severity    = "critical"
        tactic      = "Persistence"
        technique   = "T1505.003"

    strings:
        // The core payload of the China Chopper shell
        $payload = "eval(Request.Item[\""
        $payload_b64 = "eval(System.Text.Encoding.GetEncoding(65001).GetString(System.Convert.FromBase64String(Request.Item[\""

    condition:
        // Look for either the plain text or base64 encoded version
        any of them
}
