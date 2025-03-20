# Run this in PowerShell to create a legitimate shortcut
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$pwd\legitimate.lnk")
$Shortcut.TargetPath = "C:\Windows\System32\notepad.exe"
$Shortcut.Description = "Normal Notepad Shortcut"
$Shortcut.WorkingDirectory = "C:\Windows\System32"
$Shortcut.Save()
