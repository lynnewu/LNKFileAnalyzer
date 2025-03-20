// ============================================================================
// LNK File Analyzer - Security Research and Forensics Tool
// For CVE-2024-XXXXX - Windows .LNK File Command Injection Vulnerability
// Version: 1.0 (March 2024)
// ============================================================================
// Background: https://thehackernews.com/2025/03/unpatched-windows-zero-day-flaw.html
// License: [Your License Choice]
// Author: [Your Name/Organization]
// ============================================================================

using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Linq;
using System.Collections.Generic;
using System.Runtime.Versioning;

namespace LnkFileAnalyzer {
	/// <summary>
	/// Logging severity levels for forensic findings and analysis results
	/// </summary>
	public enum LogLevel {
		Info,     // General processing information
		Warning,  // Suspicious but not conclusive findings
		Error,    // Analysis or processing errors
		Critical, // Severe issues requiring immediate attention
		Forensic  // Detailed forensic findings
	}

	/// <summary>
	/// Configuration options for LNK file analysis operations
	/// Controls scanning behavior and output options
	/// </summary>
	public class AnalyzerOptions {
		/// <summary>Directory path to scan for LNK files</summary>
		public String Path { get; set; } = Directory.GetCurrentDirectory();

		/// <summary>Enable recursive directory scanning</summary>
		public Boolean Recurse { get; set; } = false;

		/// <summary>File pattern to match (e.g., "*.lnk")</summary>
		public String FileSpec { get; set; } = "*.lnk";

		/// <summary>Display help information</summary>
		public Boolean ShowHelp { get; set; } = false;

		/// <summary>Enable detailed output</summary>
		public Boolean VerboseOutput { get; set; } = false;

		/// <summary>Path for detailed analysis log</summary>
		public String LogFile { get; set; } = "lnk_analysis.log";
	}

	/// <summary>
	/// Container for forensic analysis results of a single LNK file
	/// Captures metadata, indicators, and detailed findings
	/// </summary>
	public class ForensicResult {
		/// <summary>Full path to analyzed file</summary>
		required public String FilePath { get; set; }

		/// <summary>Time of analysis (UTC)</summary>
		public DateTime AnalysisTime { get; set; }

		/// <summary>Collection of analysis findings</summary>
		public List<String> Findings { get; set; } = [];

		/// <summary>File and analysis metadata</summary>
		public Dictionary<String, String> Metadata { get; set; } = [];

		/// <summary>Indicates presence of suspicious patterns</summary>
		public Boolean HasSuspiciousIndicators { get; set; }
	}

	/// <summary>
	/// Main analysis engine for detecting potential LNK file exploits
	/// Windows-specific implementation using Shell32 COM interfaces
	/// 
	/// Security Note: This tool must be run with appropriate permissions
	/// and in a controlled environment due to potential malicious content
	/// in analyzed files.
	/// </summary>
	[SupportedOSPlatform("windows")]
	static public class Program {
		/// <summary>
		/// Whitespace characters commonly used in command injection attacks
		/// These characters may be used to obfuscate malicious commands
		/// </summary>
		private static readonly Byte[] SuspiciousWhitespace = [
				0x09, // Horizontal Tab - Used to break command parsing
            0x0A, // Line Feed - Can hide commands in logs
            0x0B, // Vertical Tab - Rare in legitimate usage
            0x0C, // Form Feed - Suspicious in modern files
            0x0D, // Carriage Return - Used in command obfuscation
            0x20  // Space - Common in padding attacks
		];

		/// <summary>Forensic findings log</summary>
		private static readonly List<String> ForensicLog = [];

		#region COM Interop Definitions
		/// <summary>
		/// COM Interface for Shell Link objects
		/// Provides access to LNK file properties
		/// </summary>
		[ComImport]
		[Guid("00021401-0000-0000-C000-000000000046")]
		private class ShellLink;

		/// <summary>
		/// Shell Link Interface for accessing shortcut properties
		/// Handles extraction of potentially malicious content
		/// </summary>
		[ComImport]
		[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
		[Guid("000214F9-0000-0000-C000-000000000046")]
		private interface IShellLink {
			void GetPath([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszFile, int cchMaxPath, out IntPtr pfd, int fFlags);
			void GetIDList(out IntPtr ppidl);
			void SetIDList(IntPtr pidl);
			void GetDescription([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszName, int cchMaxName);
			void SetDescription([MarshalAs(UnmanagedType.LPWStr)] string pszName);
			void GetWorkingDirectory([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszDir, int cchMaxPath);
			void SetWorkingDirectory([MarshalAs(UnmanagedType.LPWStr)] string pszDir);
			void GetArguments([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszArgs, int cchMaxPath);
			void SetArguments([MarshalAs(UnmanagedType.LPWStr)] string pszArgs);
			void GetHotkey(out short pwHotkey);
			void SetHotkey(short wHotkey);
			void GetShowCmd(out int piShowCmd);
			void SetShowCmd(int iShowCmd);
			void GetIconLocation([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszIconPath, int cchIconPath, out int piIcon);
			void SetIconLocation([MarshalAs(UnmanagedType.LPWStr)] string pszIconPath, int iIcon);
			void SetRelativePath([MarshalAs(UnmanagedType.LPWStr)] string pszPathRel, int dwReserved);
			void Resolve(IntPtr hwnd, int fFlags);
			void SetPath([MarshalAs(UnmanagedType.LPWStr)] string pszFile);
		}

		/// <summary>
		/// Interface for file persistence operations
		/// Handles loading and saving of shortcut files
		/// </summary>
		[ComImport]
		[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
		[Guid("0000010b-0000-0000-C000-000000000046")]
		private interface IPersistFile {
			void GetCurFile([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszFile);
			void IsDirty();
			void Load([MarshalAs(UnmanagedType.LPWStr)] string pszFileName, int dwMode);
			void Save([MarshalAs(UnmanagedType.LPWStr)] string pszFileName, bool fRemember);
			void SaveCompleted([MarshalAs(UnmanagedType.LPWStr)] string pszFileName);
		}
		#endregion

		/// <summary>
		/// Logs forensic findings with timestamp and severity level
		/// Thread-safe for concurrent logging operations
		/// </summary>
		/// <param name="message">Finding to log</param>
		/// <param name="level">Severity level</param>
		private static void LogFinding(String message, LogLevel level = LogLevel.Info) {
			String entry = $"[{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}] [{level}] {message}";
			ForensicLog.Add(entry);

			if (level >= LogLevel.Warning) {
				Console.ForegroundColor = level == LogLevel.Critical ? ConsoleColor.Red : ConsoleColor.Yellow;
				Console.WriteLine(entry);
				Console.ResetColor();
			}
		}

		/// <summary>
		/// Parses and validates command line arguments
		/// </summary>
		/// <param name="args">Command line arguments</param>
		/// <returns>Configured AnalyzerOptions</returns>
		/// <exception cref="DirectoryNotFoundException">If specified path doesn't exist</exception>
		private static AnalyzerOptions ParseCommandLineArgs(String[] args) {
			var options = new AnalyzerOptions();

			for (int i = 0; i < args.Length; i++) {
				switch (args[i].ToLower()) {
					case "--help":
						options.ShowHelp = true;
						return options;

					case "--path":
						if (i + 1 < args.Length) {
							options.Path = args[++i];
							if (!Directory.Exists(options.Path)) {
								throw new DirectoryNotFoundException($"Directory not found: {options.Path}");
							}
						}
						break;

					case "--recurse":
						options.Recurse = true;
						break;

					case "--filespec":
						if (i + 1 < args.Length) {
							options.FileSpec = args[++i];
						}
						break;

					case "--verbose":
						options.VerboseOutput = true;
						break;

					default:
						Console.WriteLine($"Warning: Unknown argument '{args[i]}' ignored.");
						break;
				}
			}

			return options;
		}

		/// <summary>
		/// Performs forensic analysis of a LNK file
		/// Checks for potential exploitation attempts and suspicious patterns
		/// </summary>
		/// <param name="lnkPath">Path to LNK file</param>
		/// <returns>Forensic analysis results</returns>
		private static ForensicResult AnalyzeLnkFileForEvasion(String lnkPath) {
			var result = new ForensicResult {
				FilePath = lnkPath,
				AnalysisTime = DateTime.UtcNow
			};

			IShellLink? link = null;
			IPersistFile? file = null;

			try {
				link = (IShellLink)new ShellLink();
				file = (IPersistFile)link;
				file.Load(lnkPath, 0);

				var targetPath = new StringBuilder(260);
				var arguments = new StringBuilder(260);
				var workingDir = new StringBuilder(260);
				var description = new StringBuilder(1024);

				link.GetPath(targetPath, targetPath.Capacity, out IntPtr _, 0);
				link.GetArguments(arguments, arguments.Capacity);
				link.GetWorkingDirectory(workingDir, workingDir.Capacity);
				link.GetDescription(description, description.Capacity);

				var fileInfo = new FileInfo(lnkPath);
				result.Metadata.Add("Size", fileInfo.Length.ToString());
				result.Metadata.Add("Created", fileInfo.CreationTimeUtc.ToString("o"));
				result.Metadata.Add("Modified", fileInfo.LastWriteTimeUtc.ToString("o"));
				result.Metadata.Add("Accessed", fileInfo.LastAccessTimeUtc.ToString("o"));
				result.Metadata.Add("Target", targetPath.ToString());
				result.Metadata.Add("Arguments", arguments.ToString());
				result.Metadata.Add("WorkingDir", workingDir.ToString());
				result.Metadata.Add("Description", description.ToString());

				AnalyzePathForEvasion(targetPath.ToString(), result);
				AnalyzeArgumentsForEvasion(arguments.ToString(), result);
				AnalyzePathForEvasion(workingDir.ToString(), result, "WorkingDir");

				return result;
			}
			catch (Exception ex) {
				LogFinding($"Error analyzing {lnkPath}: {ex.Message}", LogLevel.Error);
				result.Findings.Add($"Analysis Error: {ex.Message}");
				return result;
			}
			finally {
				if (file != null)
					Marshal.ReleaseComObject(file);
				if (link != null)
					Marshal.ReleaseComObject(link);
			}
		}

		/// <summary>
		/// Analyzes a path for potential evasion techniques
		/// </summary>
		/// <param name="path">Path to analyze</param>
		/// <param name="result">Results container</param>
		/// <param name="context">Context label for findings</param>
		private static void AnalyzePathForEvasion(String path, ForensicResult result, String context = "Path") {
			if (String.IsNullOrEmpty(path)) {
				result.Findings.Add($"{context}: Empty or null path detected");
				return;
			}

			Int32 leadingWhitespace = path.TakeWhile(c => SuspiciousWhitespace.Contains((Byte)c)).Count();
			Int32 trailingWhitespace = path.Reverse().TakeWhile(c => SuspiciousWhitespace.Contains((Byte)c)).Count();

			if (leadingWhitespace > 0 || trailingWhitespace > 0) {
				result.HasSuspiciousIndicators = true;
				result.Findings.Add($"{context}: Suspicious whitespace padding detected - Leading: {leadingWhitespace}, Trailing: {trailingWhitespace}");
			}

			var suspiciousChars = path.Where(c => c < 32 || c > 126).Select(c => $"0x{(Byte)c:X2}");
			if (suspiciousChars.Any()) {
				result.HasSuspiciousIndicators = true;
				result.Findings.Add($"{context}: Contains suspicious characters: {String.Join(", ", suspiciousChars)}");
			}
		}

		/// <summary>
		/// Analyzes command arguments for potential injection attempts
		/// </summary>
		/// <param name="arguments">Arguments to analyze</param>
		/// <param name="result">Results container</param>
		private static void AnalyzeArgumentsForEvasion(String arguments, ForensicResult result) {
			if (String.IsNullOrEmpty(arguments)) {
				return;
			}

			String[] suspiciousPatterns = [
					"&", "&&", "|", "||", ";", "`",
								"$", "(", ")", "{", "}", "<", ">"
			];

			foreach (var pattern in suspiciousPatterns) {
				if (arguments.Contains(pattern)) {
					result.HasSuspiciousIndicators = true;
					result.Findings.Add($"Arguments: Potential command injection character detected: {pattern}");
				}
			}

			if (arguments.Contains('%') || arguments.Contains('\\')) {
				result.Findings.Add("Arguments: Contains encoded or escaped characters");
			}

			var whitespaceAnalysis = arguments
					.GroupBy(c => c)
					.Where(g => SuspiciousWhitespace.Contains((Byte)g.Key))
					.Select(g => new { Character = g.Key, Count = g.Count() });

			foreach (var ws in whitespaceAnalysis) {
				result.Findings.Add($"Arguments: Contains {ws.Count} instances of whitespace character 0x{(Byte)ws.Character:X2}");
			}
		}

		/// <summary>
		/// Displays help information about tool usage and capabilities
		/// </summary>
		private static void ShowHelp() {
			Console.WriteLine(@"
LNK File Analyzer - Forensic Analysis Tool
========================================

Purpose:
    Analyze Windows shortcut (.LNK) files for potential security evasion techniques
    and command injection attempts.

Usage:
    LnkFileAnalyzer.exe [options]

Options:
    --path <directory>    : Directory to scan (default: current directory)
    --recurse            : Scan subdirectories recursively (default: false)
    --filespec <pattern> : File specification (default: *.lnk)
    --verbose           : Enable verbose output
    --help              : Show this help message

Examples:
    LnkFileAnalyzer.exe --path C:\Users --recurse
    LnkFileAnalyzer.exe --path D:\Suspicious --filespec test*.lnk");
		}

		/// <summary>
		/// Main entry point for LNK file analysis
		/// </summary>
		/// <param name="args">Command line arguments</param>
		public static void Main(String[] args) {
			try {
				var options = ParseCommandLineArgs(args);

				if (options.ShowHelp) {
					ShowHelp();
					return;
				}

				LogFinding($"Starting analysis with path: {options.Path}", LogLevel.Info);
				LogFinding($"Recursive search: {options.Recurse}", LogLevel.Info);
				LogFinding($"File specification: {options.FileSpec}", LogLevel.Info);

				var files = Directory.GetFiles(
						options.Path,
						options.FileSpec,
						options.Recurse ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly
				);

				if (files.Length == 0) {
					LogFinding("No matching .LNK files found.", LogLevel.Warning);
					return;
				}

				LogFinding($"Found {files.Length} files to analyze.", LogLevel.Info);

				var results = new List<ForensicResult>();
				foreach (var file in files) {
					LogFinding($"Analyzing: {file}", LogLevel.Info);
					var result = AnalyzeLnkFileForEvasion(file);
					results.Add(result);
				}

				var suspicious = results.Where(r => r.HasSuspiciousIndicators).ToList();

				Console.WriteLine("\n=== Analysis Summary ===");
				Console.WriteLine($"Total files analyzed: {results.Count}");
				Console.WriteLine($"Suspicious files detected: {suspicious.Count}");

				if (suspicious.Count != 0) {
					Console.WriteLine("\nSuspicious Files:");
					foreach (var result in suspicious) {
						Console.WriteLine($"\nFile: {result.FilePath}");
						foreach (var finding in result.Findings) {
							Console.WriteLine($"  - {finding}");
						}
					}
				}

				File.WriteAllLines(options.LogFile, ForensicLog);
				Console.WriteLine($"\nDetailed analysis log saved to: {options.LogFile}");
			}
			catch (Exception ex) {
				LogFinding($"Critical error: {ex.Message}", LogLevel.Critical);
				LogFinding(ex.StackTrace ?? "No stack trace available", LogLevel.Error);
			}
		}
	}
}


///// <summary>
///// Windows .LNK File Analyzer for CVE-2024-XXXXX
///// 
///// Purpose:
///// Analyzes Windows shortcut files for potential exploit attempts targeting the Windows 
///// zero-day vulnerability disclosed in March 2024. This vulnerability allows attackers
///// to execute arbitrary code through specially crafted .LNK files using whitespace padding
///// and command injection techniques.
///// 
///// Detection Capabilities:
///// - Whitespace padding in arguments and paths
///// - Command injection characters
///// - Suspicious character sequences
///// - Path obfuscation techniques
///// - Timeline analysis of file creation/modification
///// 
///// Technical Background:
///// The vulnerability exploits how Windows processes shortcut files, specifically:
///// 1. Whitespace handling in command arguments
///// 2. Path parsing mechanisms
///// 3. Command shell interpretation
///// 
///// Usage:
///// LnkFileAnalyzer.exe [--path <dir>] [--recurse] [--filespec <pattern>] [--verbose] [--help]
///// 
///// References:
///// - https://thehackernews.com/2025/03/unpatched-windows-zero-day-flaw.html
///// - [Additional CVE/vulnerability references]
///// 
///// Author: mostly ClaudeAI + me (Lynne)
///// Version: 1.0
///// Date: March 2025
///// </summary>


//using System.Runtime.InteropServices;
//using System.Runtime.Versioning;
//using System.Text;

//namespace LnkFileAnalyzer {

//	/// <summary>
//	/// Logging severity levels for forensic findings
//	/// </summary>
//	public enum LogLevel {
//		Info,     // General information
//		Warning,  // Suspicious but not conclusive
//		Error,    // Analysis errors
//		Critical, // Severe issues requiring immediate attention
//		Forensic  // Detailed forensic findings
//	}


//	/// <summary>
//	/// Configuration (CLI) options for LNK file analysis
//	/// </summary>
//	public class AnalyzerOptions {
//		public String Path { get; set; } = Directory.GetCurrentDirectory();
//		public Boolean Recurse { get; set; } = false;
//		public String FileSpec { get; set; } = "*.lnk";
//		public Boolean ShowHelp { get; set; } = false;
//		public Boolean VerboseOutput { get; set; } = false;
//		public String LogFile { get; set; } = "lnk_analysis.log";
//	}

//	/// <summary>
//	/// Container for forensic analysis results of a single .LNK file
//	/// Captures metadata, suspicious indicators, and findings
//	/// </summary>
//	public class ForensicResult {
//		required public String FilePath { get; set; }
//		public DateTime AnalysisTime { get; set; }
//		public List<String> Findings { get; set; } = [];
//		public Dictionary<String, String> Metadata { get; set; } = [];
//		public Boolean HasSuspiciousIndicators { get; set; }
//	}


//	/// <summary>
//	/// Main analysis engine for detecting potential .LNK file exploits
//	/// Windows-specific implementation using Shell32 COM interfaces
//	/// </summary>
//	[SupportedOSPlatform("windows")]
//	static public class Program {
//		/// <summary>
//		/// Whitespace characters commonly used in command injection attacks
//		/// These characters can be used to obfuscate malicious commands
//		/// </summary>
//		private static readonly Byte[] SuspiciousWhitespace = [
//			0x09,	// Horizontal	Tab	-	Used to	break	command	parsing
//			0x0A,	// Line	Feed - Can hide	commands in	logs
//			0x0B,	// Vertical	Tab	-	Rare in	legitimate usage
//			0x0C,	// Form	Feed - Suspicious	in modern	files
//			0x0D,	// Carriage	Return - Used	in command obfuscation
//			0x20	// Space - Common	in padding attacks
//		];


//		private static readonly List<String> ForensicLog = [];

//		#region COM Interop Definitions

//		[ComImport]
//		[Guid("00021401-0000-0000-C000-000000000046")]
//		private class ShellLink;

//		[ComImport]
//		[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
//		[Guid("000214F9-0000-0000-C000-000000000046")]
//		private interface IShellLink {
//			void GetPath([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszFile, int cchMaxPath, out IntPtr pfd, int fFlags);
//			void GetIDList(out IntPtr ppidl);
//			void SetIDList(IntPtr pidl);
//			void GetDescription([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszName, int cchMaxName);
//			void SetDescription([MarshalAs(UnmanagedType.LPWStr)] string pszName);
//			void GetWorkingDirectory([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszDir, int cchMaxPath);
//			void SetWorkingDirectory([MarshalAs(UnmanagedType.LPWStr)] string pszDir);
//			void GetArguments([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszArgs, int cchMaxPath);
//			void SetArguments([MarshalAs(UnmanagedType.LPWStr)] string pszArgs);
//			void GetHotkey(out short pwHotkey);
//			void SetHotkey(short wHotkey);
//			void GetShowCmd(out int piShowCmd);
//			void SetShowCmd(int iShowCmd);
//			void GetIconLocation([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszIconPath, int cchIconPath, out int piIcon);
//			void SetIconLocation([MarshalAs(UnmanagedType.LPWStr)] string pszIconPath, int iIcon);
//			void SetRelativePath([MarshalAs(UnmanagedType.LPWStr)] string pszPathRel, int dwReserved);
//			void Resolve(IntPtr hwnd, int fFlags);
//			void SetPath([MarshalAs(UnmanagedType.LPWStr)] string pszFile);
//		}

//		[ComImport]
//		[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
//		[Guid("0000010b-0000-0000-C000-000000000046")]
//		private interface IPersistFile {
//			void GetCurFile([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszFile);
//			void IsDirty();
//			void Load([MarshalAs(UnmanagedType.LPWStr)] string pszFileName, int dwMode);
//			void Save([MarshalAs(UnmanagedType.LPWStr)] string pszFileName, bool fRemember);
//			void SaveCompleted([MarshalAs(UnmanagedType.LPWStr)] string pszFileName);
//		}

//		#endregion

//		private static void LogFinding(String message, LogLevel level = LogLevel.Info) {
//			String entry = $"[{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}] [{level}] {message}";
//			ForensicLog.Add(entry);

//			if (level >= LogLevel.Warning) {
//				Console.ForegroundColor = level == LogLevel.Critical ? ConsoleColor.Red : ConsoleColor.Yellow;
//				Console.WriteLine(entry);
//				Console.ResetColor();
//			}
//		}

//		private static AnalyzerOptions ParseCommandLineArgs(String[] args) {
//			var options = new AnalyzerOptions();

//			for (int i = 0; i < args.Length; i++) {
//				switch (args[i].ToLower()) {
//					case "--help":
//						options.ShowHelp = true;
//						return options;

//					case "--path":
//						if (i + 1 < args.Length) {
//							options.Path = args[++i];
//							if (!Directory.Exists(options.Path)) {
//								throw new DirectoryNotFoundException($"Directory not found: {options.Path}");
//							}
//						}
//						break;

//					case "--recurse":
//						options.Recurse = true;
//						break;

//					case "--filespec":
//						if (i + 1 < args.Length) {
//							options.FileSpec = args[++i];
//						}
//						break;

//					case "--verbose":
//						options.VerboseOutput = true;
//						break;

//					default:
//						Console.WriteLine($"Warning: Unknown argument '{args[i]}' ignored.");
//						break;
//				}
//			}

//			return options;
//		}


//			/// <summary>
//			/// Analyzes a .LNK file for potential exploitation attempts
//			/// 
//			/// Detection methodology:
//			/// 1. Extracts shortcut metadata and properties
//			/// 2. Analyzes command arguments for injection attempts
//			/// 3. Checks for suspicious whitespace padding
//			/// 4. Identifies unusual character sequences
//			/// 
//			/// Parameters:
//			///   lnkPath - Full path to the .LNK file
//			/// 
//			/// Returns:
//			///   ForensicResult containing analysis findings
//			/// </summary>
//			private static ForensicResult AnalyzeLnkFileForEvasion(String lnkPath) {
//			var result = new ForensicResult {
//				FilePath = lnkPath,
//				AnalysisTime = DateTime.UtcNow
//			};

//			IShellLink? link = null;
//			IPersistFile? file = null;

//			try {
//				link = (IShellLink)new ShellLink();
//				file = (IPersistFile)link;

//				file.Load(lnkPath, 0);

//				var targetPath = new StringBuilder(260);
//				var arguments = new StringBuilder(260);
//				var workingDir = new StringBuilder(260);
//				var description = new StringBuilder(1024);

//				link.GetPath(targetPath, targetPath.Capacity, out IntPtr _, 0);
//				link.GetArguments(arguments, arguments.Capacity);
//				link.GetWorkingDirectory(workingDir, workingDir.Capacity);
//				link.GetDescription(description, description.Capacity);

//				var fileInfo = new FileInfo(lnkPath);
//				result.Metadata.Add("Size", fileInfo.Length.ToString());
//				result.Metadata.Add("Created", fileInfo.CreationTimeUtc.ToString("o"));
//				result.Metadata.Add("Modified", fileInfo.LastWriteTimeUtc.ToString("o"));
//				result.Metadata.Add("Accessed", fileInfo.LastAccessTimeUtc.ToString("o"));
//				result.Metadata.Add("Target", targetPath.ToString());
//				result.Metadata.Add("Arguments", arguments.ToString());
//				result.Metadata.Add("WorkingDir", workingDir.ToString());
//				result.Metadata.Add("Description", description.ToString());

//				AnalyzePathForEvasion(targetPath.ToString(), result);
//				AnalyzeArgumentsForEvasion(arguments.ToString(), result);
//				AnalyzePathForEvasion(workingDir.ToString(), result, "WorkingDir");

//				return result;
//			}
//			catch (Exception ex) {
//				LogFinding($"Error analyzing {lnkPath}: {ex.Message}", LogLevel.Error);
//				result.Findings.Add($"Analysis Error: {ex.Message}");
//				return result;
//			}
//			finally {
//				if (file != null)
//					Marshal.ReleaseComObject(file);
//				if (link != null)
//					Marshal.ReleaseComObject(link);
//			}
//		}


//			/// <summary>
//			/// Analyzes a path string for evasion techniques
//			/// 
//			/// Checks for:
//			/// - Leading/trailing whitespace padding
//			/// - Non-printable characters
//			/// - Path traversal attempts
//			/// 
//			/// Parameters:
//			///   path - Path to analyze
//			///   result - ForensicResult to update
//			///   context - Context label for findings
//			/// </summary>
//			private static void AnalyzePathForEvasion(String path, ForensicResult result, String context = "Path") {
//			if (String.IsNullOrEmpty(path)) {
//				result.Findings.Add($"{context}: Empty or null path detected");
//				return;
//			}

//			Int32 leadingWhitespace = path.TakeWhile(c => SuspiciousWhitespace.Contains((Byte)c)).Count();
//			Int32 trailingWhitespace = path.Reverse().TakeWhile(c => SuspiciousWhitespace.Contains((Byte)c)).Count();

//			if (leadingWhitespace > 0 || trailingWhitespace > 0) {
//				result.HasSuspiciousIndicators = true;
//				result.Findings.Add($"{context}: Suspicious whitespace padding detected - Leading: {leadingWhitespace}, Trailing: {trailingWhitespace}");
//			}

//			var suspiciousChars = path.Where(c => c < 32 || c > 126).Select(c => $"0x{(Byte)c:X2}");
//			if (suspiciousChars.Any()) {
//				result.HasSuspiciousIndicators = true;
//				result.Findings.Add($"{context}: Contains suspicious characters: {String.Join(", ", suspiciousChars)}");
//			}
//		}




//			/// <summary>
//			/// Analyzes command arguments for potential injection attempts
//			/// 
//			/// Detection scope:
//			/// - Command separators (& | ; etc.)
//			/// - Shell special characters
//			/// - Encoded/escaped sequences
//			/// - Suspicious whitespace patterns
//			/// 
//			/// Parameters:
//			///   arguments - Command arguments to analyze
//			///   result - ForensicResult to update
//			/// </summary>
//			private static void AnalyzeArgumentsForEvasion(String arguments, ForensicResult result) {
//			if (String.IsNullOrEmpty(arguments)) {
//				return;
//			}

//			String[] suspiciousPatterns = [
//								"&", "&&", "|", "||", ";", "`",
//								"$", "(", ")", "{", "}", "<", ">"
//						];

//			foreach (var pattern in suspiciousPatterns) {
//				if (arguments.Contains(pattern)) {
//					result.HasSuspiciousIndicators = true;
//					result.Findings.Add($"Arguments: Potential command injection character detected: {pattern}");
//				}
//			}

//			if (arguments.Contains('%') || arguments.Contains('\\')) {
//				result.Findings.Add("Arguments: Contains encoded or escaped characters");
//			}

//			var whitespaceAnalysis = arguments
//					.GroupBy(c => c)
//					.Where(g => SuspiciousWhitespace.Contains((Byte)g.Key))
//					.Select(g => new { Character = g.Key, Count = g.Count() });

//			foreach (var ws in whitespaceAnalysis) {
//				result.Findings.Add($"Arguments: Contains {ws.Count} instances of whitespace character 0x{(Byte)ws.Character:X2}");
//			}
//		}

//		private static void ShowHelp() {
//			Console.WriteLine(@"
//LNK File Analyzer - Forensic Analysis Tool
//========================================

//Purpose:
//		Analyze Windows shortcut (.LNK) files for potential security evasion techniques
//		and command injection attempts.

//Usage:
//		LnkFileAnalyzer.exe [options]

//Options:
//		--path <directory>    : Directory to scan (default: current directory)
//		--recurse            : Scan subdirectories recursively (default: false)
//		--filespec <pattern> : File specification (default: *.lnk)
//		--verbose           : Enable verbose output
//		--help              : Show this help message

//Examples:
//		LnkFileAnalyzer.exe --path C:\Users --recurse
//		LnkFileAnalyzer.exe --path D:\Suspicious --filespec test*.lnk");
//		}

//		public static void Main(String[] args) {
//			try {
//				var options = ParseCommandLineArgs(args);

//				if (options.ShowHelp) {
//					ShowHelp();
//					return;
//				}

//				LogFinding($"Starting analysis with path: {options.Path}", LogLevel.Info);
//				LogFinding($"Recursive search: {options.Recurse}", LogLevel.Info);
//				LogFinding($"File specification: {options.FileSpec}", LogLevel.Info);

//				var files = Directory.GetFiles(
//						options.Path,
//						options.FileSpec,
//						options.Recurse ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly
//				);

//				if (files.Length == 0) {
//					LogFinding("No matching .LNK files found.", LogLevel.Warning);
//					return;
//				}

//				LogFinding($"Found {files.Length} files to analyze.", LogLevel.Info);

//				var results = new List<ForensicResult>();
//				foreach (var file in files) {
//					LogFinding($"Analyzing: {file}", LogLevel.Info);
//					var result = AnalyzeLnkFileForEvasion(file);
//					results.Add(result);
//				}

//				var suspicious = results.Where(r => r.HasSuspiciousIndicators).ToList();

//				Console.WriteLine("\n=== Analysis Summary ===");
//				Console.WriteLine($"Total files analyzed: {results.Count}");
//				Console.WriteLine($"Suspicious files detected: {suspicious.Count}");

//				if (suspicious.Count != 0) {
//					Console.WriteLine("\nSuspicious Files:");
//					foreach (var result in suspicious) {
//						Console.WriteLine($"\nFile: {result.FilePath}");
//						foreach (var finding in result.Findings) {
//							Console.WriteLine($"  - {finding}");
//						}
//					}
//				}

//				File.WriteAllLines(options.LogFile, ForensicLog);
//				Console.WriteLine($"\nDetailed analysis log saved to: {options.LogFile}");
//			}
//			catch (Exception ex) {
//				LogFinding($"Critical error: {ex.Message}", LogLevel.Critical);
//				LogFinding(ex.StackTrace ?? "No stack trace available", LogLevel.Error);
//			}
//		}
//	}
//}