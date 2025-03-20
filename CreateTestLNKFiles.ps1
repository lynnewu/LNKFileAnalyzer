# Test Case Generator for LNK File Analyzer
# Creates test .LNK files with various detection patterns
# SAFE VERSION - NO COMMAND EXECUTION

$TestFolder = ".\LNK_Test_Files"
New-Item -ItemType Directory -Force -Path $TestFolder

$WshShell = New-Object -comObject WScript.Shell

# 1. Legitimate shortcut (control case)
$Shortcut = $WshShell.CreateShortcut("$TestFolder\01_legitimate.lnk")
$Shortcut.TargetPath = "C:\Windows\System32\notepad.exe"
$Shortcut.Description = "Normal Notepad Shortcut"
$Shortcut.WorkingDirectory = "C:\Windows\System32"
$Shortcut.Save()
Write-Host "Created: 01_legitimate.lnk"

# 2. Basic whitespace padding
$Shortcut = $WshShell.CreateShortcut("$TestFolder\02_whitespace_padding.lnk")
$Shortcut.TargetPath = "C:\Windows\System32\cmd.exe"
$Shortcut.Arguments = "    /k echo This is a test    "
$Shortcut.Description = "Basic Whitespace Padding Test"
$Shortcut.Save()
Write-Host "Created: 02_whitespace_padding.lnk"

# 3. Command injection pattern
$Shortcut = $WshShell.CreateShortcut("$TestFolder\03_command_injection.lnk")
$Shortcut.TargetPath = "C:\Windows\System32\cmd.exe"
$Shortcut.Arguments = "/k echo command1 && echo command2 || echo command3"
$Shortcut.Description = "Command Injection Pattern Test"
$Shortcut.Save()
Write-Host "Created: 03_command_injection.lnk"

# 4. Special whitespace characters
$Shortcut = $WshShell.CreateShortcut("$TestFolder\04_special_whitespace.lnk")
$Shortcut.TargetPath = "C:\Windows\System32\cmd.exe"
$Shortcut.Arguments = " /k echo test "
$Shortcut.WorkingDirectory = "C:\Windows\System32"
$Shortcut.Save()
Write-Host "Created: 04_special_whitespace.lnk"

# 5. Environment variable pattern
$Shortcut = $WshShell.CreateShortcut("$TestFolder\05_env_injection.lnk")
$Shortcut.TargetPath = "%COMSPEC%"
$Shortcut.Arguments = "/k echo %SYSTEMROOT%"
$Shortcut.Description = "Environment Variable Pattern Test"
$Shortcut.Save()
Write-Host "Created: 05_env_injection.lnk"

# 6. Multiple command pattern
$Shortcut = $WshShell.CreateShortcut("$TestFolder\06_multiple_commands.lnk")
$Shortcut.TargetPath = "C:\Windows\System32\cmd.exe"
$Shortcut.Arguments = "/k echo test1 & echo test2 ; echo test3"
$Shortcut.Description = "Multiple Command Pattern Test"
$Shortcut.Save()
Write-Host "Created: 06_multiple_commands.lnk"

# 7. Command substitution pattern
$Shortcut = $WshShell.CreateShortcut("$TestFolder\07_command_substitution.lnk")
$Shortcut.TargetPath = "C:\Windows\System32\cmd.exe"
$Shortcut.Arguments = "/k echo $(test) && echo ${test}"
$Shortcut.Description = "Command Substitution Pattern Test"
$Shortcut.Save()
Write-Host "Created: 07_command_substitution.lnk"

# 8. Path traversal pattern
$Shortcut = $WshShell.CreateShortcut("$TestFolder\08_path_traversal.lnk")
$Shortcut.TargetPath = "..\..\..\Windows\System32\cmd.exe"
$Shortcut.Arguments = "/k echo ..\..\test"
$Shortcut.Description = "Path Traversal Pattern Test"
$Shortcut.Save()
Write-Host "Created: 08_path_traversal.lnk"

# 9. Mixed patterns
$Shortcut = $WshShell.CreateShortcut("$TestFolder\09_mixed_patterns.lnk")
$Shortcut.TargetPath = "C:\Windows\System32\cmd.exe"
$Shortcut.Arguments = "   /k echo test && echo test2  "
$Shortcut.WorkingDirectory = "  C:\Windows\System32  "
$Shortcut.Description = "Mixed Pattern Test"
$Shortcut.Save()
Write-Host "Created: 09_mixed_patterns.lnk"

# 10. PowerShell pattern
$Shortcut = $WshShell.CreateShortcut("$TestFolder\10_powershell_exec.lnk")
$Shortcut.TargetPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
$Shortcut.Arguments = "-NoP -NonI -W Hidden -Exec Bypass -Command echo test"
$Shortcut.Description = "PowerShell Pattern Test"
$Shortcut.Save()
Write-Host "Created: 10_powershell_exec.lnk"

# 11. Space padding
$Shortcut = $WshShell.CreateShortcut("$TestFolder\11_space_padding.lnk")
$Shortcut.TargetPath = "C:\Windows\System32\cmd.exe"
$Shortcut.Arguments = "              /k echo test              "
$Shortcut.Description = "Excessive Space Padding Test"
$Shortcut.Save()
Write-Host "Created: 11_space_padding.lnk"

# 12. Nested command pattern
$Shortcut = $WshShell.CreateShortcut("$TestFolder\12_nested_execution.lnk")
$Shortcut.TargetPath = "C:\Windows\System32\cmd.exe"
$Shortcut.Arguments = '/k for /f "tokens=*" %i in (''dir /b'') do @echo %i'
$Shortcut.Description = "Nested Command Pattern Test"
$Shortcut.Save()
Write-Host "Created: 12_nested_execution.lnk"

Write-Host "`nCreated test files in: $TestFolder"
Write-Host "Total test cases: 12"
Write-Host "`nTest case summary:"
Write-Host "01: Legitimate shortcut (control)"
Write-Host "02: Basic whitespace padding"
Write-Host "03: Command injection pattern"
Write-Host "04: Special whitespace characters"
Write-Host "05: Environment variable pattern"
Write-Host "06: Multiple command pattern"
Write-Host "07: Command substitution pattern"
Write-Host "08: Path traversal pattern"
Write-Host "09: Mixed patterns"
Write-Host "10: PowerShell pattern"
Write-Host "11: Space padding"
Write-Host "12: Nested command pattern"

# Cleanup COM object
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($WshShell) | Out-Null

