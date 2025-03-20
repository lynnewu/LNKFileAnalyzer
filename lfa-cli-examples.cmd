# Basic usage - analyze current directory
c:\src-ssb\LnkFileAnalyzer\LnkFileAnalyzer.exe

# Analyze a specific directory
c:\src-ssb\LnkFileAnalyzer\LnkFileAnalyzer.exe --path "c:\Users\Administrator\Desktop"

# Analyze with recursive search
c:\src-ssb\LnkFileAnalyzer\LnkFileAnalyzer.exe --path "c:\Users" --recurse

# Short argument form
c:\src-ssb\LnkFileAnalyzer\LnkFileAnalyzer.exe -p "c:\Users" -r

# Specific file pattern
c:\src-ssb\LnkFileAnalyzer\LnkFileAnalyzer.exe --path "c:\Program Files" --filespec "*.lnk"

# Analyze a single specific file
c:\src-ssb\LnkFileAnalyzer\LnkFileAnalyzer.exe --path "c:\Users\Administrator\Desktop\suspicious.lnk"

# Directly specify file with path option
c:\src-ssb\LnkFileAnalyzer\LnkFileAnalyzer.exe -p "c:\Users\Administrator\Desktop\suspicious.lnk"

# Custom log file
c:\src-ssb\LnkFileAnalyzer\LnkFileAnalyzer.exe --path "c:\Users" --logfile "forensic_results.log"

# Combining multiple options
c:\src-ssb\LnkFileAnalyzer\LnkFileAnalyzer.exe -p "c:\Users" -r -f "suspicious*.lnk" -v

# Analyze test files from directory
c:\src-ssb\LnkFileAnalyzer\LnkFileAnalyzer.exe --path "c:\src-ssb\LnkFileAnalyzer\LNK_Test_Files"

# Analyze a specific file with verbose output
c:\src-ssb\LnkFileAnalyzer\LnkFileAnalyzer.exe -p "c:\src-ssb\LnkFileAnalyzer\LNK_Test_Files\03_command_injection.lnk" -v

# Help information
c:\src-ssb\LnkFileAnalyzer\LnkFileAnalyzer.exe --help

# Mixed case arguments (will work due to case insensitivity)
c:\src-ssb\LnkFileAnalyzer\LnkFileAnalyzer.exe --PATH "c:\Users" --RecUrsE

# Directory with trailing slash works too
c:\src-ssb\LnkFileAnalyzer\LnkFileAnalyzer.exe --path "c:\src-ssb\LnkFileAnalyzer\LNK_Test_Files\"

# Multiple specific files with wildcard
c:\src-ssb\LnkFileAnalyzer\LnkFileAnalyzer.exe -p "c:\src-ssb\LnkFileAnalyzer\LNK_Test_Files" -f "*injection*.lnk"
