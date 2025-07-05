# src/rules/rule_engine.py

MITRE_RULE_ENGINE = {
    # Process & Command Line Keywords
    "powershell.exe -enc": "T1059.001",
    "mimikatz": "T1003.001",
    "PsExec.exe": "T1569.002",
    "whoami": "T1033",
    "net user": "T1087.001",
    "nltest /dclist": "T1016",
    "wmic": "T1047", # Windows Management Instrumentation

    # Registry Persistence Keywords
    "CurrentVersion\\Run": "T1547.001",

    # File & Attachment Keywords
    "invoice_2025.zip": "T1566.001", # Phishing: Spearphishing Attachment
    "invoice_2025.exe": "T1204.002", # User Execution: Malicious File
}