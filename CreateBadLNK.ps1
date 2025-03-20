# Run this in PowerShell to create a suspicious shortcut with command injection patterns
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$pwd\malicious.lnk")
$Shortcut.TargetPath = "   cmd.exe   "  # Notice the padding
$Shortcut.Arguments = "  /c  calc.exe && notepad.exe  `t`n  "  # Includes command injection and suspicious whitespace
$Shortcut.Description = "Suspicious Command Execution"
$Shortcut.WorkingDirectory = "`t C:\Windows\System32 `n"  # More suspicious whitespace
$Shortcut.Save()
