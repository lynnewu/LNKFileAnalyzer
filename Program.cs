/*
===========================================================================
LNK File Analyzer - Security Research and Forensics Tool
For CVE-2024-XXXXX - Windows .LNK File Command Injection Vulnerability
Version: 1.2 (2025-03-20)
===========================================================================
 
Background: https://thehackernews.com/2025/03/unpatched-windows-zero-day-flaw.html
 
Author: us.anthropic.claude-3-7-sonnet-20250219-v1:0 & lwhitehorn@silverstarbrands.com
 
===========================================================================
License:  https://mit-license.org/
 
The MIT License (MIT)
Copyright © 2025 <copyright holders>
 
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
 
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
 
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 
============================================================================
*/

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security;
using System.Text;

#pragma warning disable CA1416 // Validate platform compatibility

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

		/// <summary>Continue on errors (skip problematic files)</summary>
		public Boolean ContinueOnErrors { get; set; } = true;
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

		/// <summary>Analysis completed successfully</summary>
		public Boolean AnalysisSucceeded { get; set; } = true;

		/// <summary>Error message if analysis failed</summary>
		public String ErrorMessage { get; set; } = String.Empty;
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
		/// Container for whitespace character statistics
		/// </summary>
		private class CharacterCountInfo {
			/// <summary>The character being counted</summary>
			public Char Character { get; set; }

			/// <summary>Number of occurrences</summary>
			public Int32 Count { get; set; }
		}

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

		/// <summary>Error count for reporting</summary>
		private static Int32 TotalErrorCount = 0;

		#region COM Interop Definitions
		/// <summary>
		/// COM Interface for Shell Link objects
		/// Provides access to LNK file properties
		/// </summary>
		[ComImport]
		[Guid("00021401-0000-0000-C000-000000000046")]
		private class ShellLink;


		///// Shell Link Interface for accessing shortcut properties
		///// Handles extraction of potentially malicious content
		///// </summary>
		//[ComImport]
		//[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
		//[Guid("000214F9-0000-0000-C000-000000000046")]
		//private interface IShellLink {
		//	void GetPath([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszFile, int cchMaxPath, out IntPtr pfd, int fFlags);
		//	void GetIDList(out IntPtr ppidl);
		//	void SetIDList(IntPtr pidl);
		//	void GetDescription([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszName, int cchMaxName);
		//	void SetDescription([MarshalAs(UnmanagedType.LPWStr)] string pszName);
		//	void GetWorkingDirectory([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszDir, int cchMaxPath);
		//	void SetWorkingDirectory([MarshalAs(UnmanagedType.LPWStr)] string pszDir);
		//	void GetArguments([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszArgs, int cchMaxPath);
		//	void SetArguments([MarshalAs(UnmanagedType.LPWStr)] string pszArgs);
		//	void GetHotkey(out short pwHotkey);
		//	void SetHotkey(short wHotkey);
		//	void GetShowCmd(out int piShowCmd);
		//	void SetShowCmd(int iShowCmd);
		//	void GetIconLocation([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszIconPath, int cchIconPath, out int piIcon);
		//	void SetIconLocation([MarshalAs(UnmanagedType.LPWStr)] string pszIconPath, int iIcon);
		//	void SetRelativePath([MarshalAs(UnmanagedType.LPWStr)] string pszPathRel, int dwReserved);
		//	void Resolve(IntPtr hwnd, int fFlags);
		//	void SetPath([MarshalAs(UnmanagedType.LPWStr)] string pszFile);
		//}

		/// <summary>
		/// Shell Link Interface (Unicode version) for accessing shortcut properties
		/// Based on official documentation for IShellLinkW
		/// </summary>
		[ComImport]
		[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
		[Guid("000214F9-0000-0000-C000-000000000046")]
		private interface IShellLink {
			/// <summary>
			/// Retrieves the path and filename of a shell link object
			/// </summary>
			/// <param name="pszFile">Buffer to receive the path</param>
			/// <param name="cch">Size of the buffer in characters</param>
			/// <param name="pfd">WIN32_FIND_DATAW structure or IntPtr.Zero</param>
			/// <param name="fFlags">Flags specifying the type of path information to retrieve</param>
			void GetPath([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszFile, int cch,
									 [In, Out, MarshalAs(UnmanagedType.Struct)] ref WIN32_FIND_DATAW pfd,
									 uint fFlags);

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
		/// WIN32_FIND_DATAW structure for use with IShellLinkW
		/// </summary>
		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		private struct WIN32_FIND_DATAW {
			public uint dwFileAttributes;
			public FILETIME ftCreationTime;
			public FILETIME ftLastAccessTime;
			public FILETIME ftLastWriteTime;
			public uint nFileSizeHigh;
			public uint nFileSizeLow;
			public uint dwReserved0;
			public uint dwReserved1;
			[MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
			public string cFileName;
			[MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)]
			public string cAlternateFileName;
		}

		/// <summary>
		/// FILETIME structure for use with WIN32_FIND_DATAW
		/// </summary>
		[StructLayout(LayoutKind.Sequential)]
		private struct FILETIME {
			public uint dwLowDateTime;
			public uint dwHighDateTime;
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
		/// Also outputs to debug if a debugger is attached
		/// </summary>
		/// <param name="message">Finding to log</param>
		/// <param name="level">Severity level</param>
		private static void LogFinding(String message, LogLevel level = LogLevel.Info) {
			String entry = $"[{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}] [{level}] {message}";
			ForensicLog.Add(entry);

			// Output to debug if debugger is attached
			if (Debugger.IsAttached) {
				Debug.Print($"{entry}");
			}

			if (level >= LogLevel.Warning) {
				Console.ForegroundColor = level == LogLevel.Critical ? ConsoleColor.Red : ConsoleColor.Yellow;
				Console.WriteLine(entry);
				Console.ResetColor();
			}
		}

		/// <summary>
		/// Safely attempts to get additional file information
		/// Handles access denied and other common exceptions
		/// </summary>
		/// <param name="filePath">Path to the file</param>
		/// <param name="result">ForensicResult to update</param>
		private static void SafeGetFileInfo(String filePath, ForensicResult result) {
			try {
				FileInfo fileInfo = new FileInfo(filePath);
				result.Metadata.Add("Size", fileInfo.Length.ToString());

				try {
					result.Metadata.Add("Created", fileInfo.CreationTimeUtc.ToString("o"));
				}
				catch (Exception ex) {
					result.Metadata.Add("Created", $"Error: {ex.Message}");
				}

				try {
					result.Metadata.Add("Modified", fileInfo.LastWriteTimeUtc.ToString("o"));
				}
				catch (Exception ex) {
					result.Metadata.Add("Modified", $"Error: {ex.Message}");
				}

				try {
					result.Metadata.Add("Accessed", fileInfo.LastAccessTimeUtc.ToString("o"));
				}
				catch (Exception ex) {
					result.Metadata.Add("Accessed", $"Error: {ex.Message}");
				}

				try {
					result.Metadata.Add("Attributes", fileInfo.Attributes.ToString());
				}
				catch (Exception ex) {
					result.Metadata.Add("Attributes", $"Error: {ex.Message}");
				}
			}
			catch (UnauthorizedAccessException ex) {
				result.Metadata.Add("FileInfo", $"Access denied: {ex.Message}");
			}
			catch (SecurityException ex) {
				result.Metadata.Add("FileInfo", $"Security exception: {ex.Message}");
			}
			catch (Exception ex) {
				result.Metadata.Add("FileInfo", $"Error: {ex.Message}");
			}
		}

		/// <summary>
		/// Parses and validates command line arguments with case-insensitive matching
		/// Handles various path formats and boolean flag values with improved error handling
		/// </summary>
		/// <param name="args">Command line arguments</param>
		/// <returns>Configured AnalyzerOptions</returns>
		private static AnalyzerOptions ParseCommandLineArgs(String[] args) {
			AnalyzerOptions options = new AnalyzerOptions();
			// Initialize with default
			options.FileSpec = "*.lnk";

			try {
				for (Int32 i = 0; i < args.Length; i++) {
					if (i >= args.Length) break; // Safety check

					String arg = args[i].ToLowerInvariant();  // Case-insensitive matching

					if (arg == "--help" || arg == "-h" || arg == "-?") {
						options.ShowHelp = true;
						return options;
					}
					else if ((arg == "--path" || arg == "-p") && i + 1 < args.Length) {
						i++;
						String pathArg = args[i];

						try {
							// Handle wildcard in path by extracting directory portion
							if (pathArg.Contains('*') || pathArg.Contains('?')) {
								String dir = Path.GetDirectoryName(pathArg) ?? Directory.GetCurrentDirectory();
								options.Path = dir;
								options.FileSpec = Path.GetFileName(pathArg);
							}
							else {
								options.Path = pathArg;

								// Handle path that includes filename or pattern
								if (Path.HasExtension(options.Path)) {
									options.FileSpec = Path.GetFileName(options.Path);
									options.Path = Path.GetDirectoryName(options.Path) ?? Directory.GetCurrentDirectory();
								}
								// Handle trailing backslash
								else if (options.Path.EndsWith('\\') || options.Path.EndsWith('/')) {
									options.Path = options.Path.TrimEnd('\\', '/');
									// Keep default filespec (*.lnk)
								}
							}

							if (!Directory.Exists(options.Path)) {
								// Try to find a closest parent directory that exists
								String testPath = options.Path;
								while (!String.IsNullOrEmpty(testPath) && !Directory.Exists(testPath) &&
											testPath.Contains(Path.DirectorySeparatorChar)) {
									testPath = Path.GetDirectoryName(testPath) ?? String.Empty;
								}

								if (!String.IsNullOrEmpty(testPath) && Directory.Exists(testPath)) {
									LogFinding($"Directory '{options.Path}' not found. Using closest parent: '{testPath}'", LogLevel.Warning);
									options.Path = testPath;
								}
								else {
									throw new DirectoryNotFoundException($"Directory not found: {options.Path}");
								}
							}
						}
						catch (Exception ex) {
							LogFinding($"Error processing path argument '{pathArg}': {ex.Message}", LogLevel.Error);
							// Default to current directory if path is invalid
							options.Path = Directory.GetCurrentDirectory();
							LogFinding($"Using current directory instead: {options.Path}", LogLevel.Warning);
						}
					}
					else if (arg == "--recurse" || arg == "-r") {
						options.Recurse = true;

						// Skip any "true" or "false" that might follow (treat as separate arg)
						if (i + 1 < args.Length) {
							String boolValue = args[i + 1].ToLowerInvariant();
							if (boolValue == "true" || boolValue == "false") {
								options.Recurse = boolValue == "true";
								i++; // Skip the value in next iteration
							}
						}
					}
					else if ((arg == "--filespec" || arg == "-f") && i + 1 < args.Length) {
						i++;
						String fileSpecArg = args[i];

						try {
							// Check if single "*" or empty value - keep default *.lnk
							if (fileSpecArg == "*" || String.IsNullOrWhiteSpace(fileSpecArg)) {
								// Keep the default "*.lnk"
								LogFinding($"Using default file specification: {options.FileSpec}", LogLevel.Info);
							}
							else {
								options.FileSpec = fileSpecArg;

								// If no extension specified and not a wildcard pattern, assume .lnk
								if (!options.FileSpec.Contains('.') && !options.FileSpec.Contains('*')) {
									options.FileSpec += ".lnk";
								}
							}

							// If filespec includes path, extract it
							if (options.FileSpec.Contains('\\') || options.FileSpec.Contains('/')) {
								String fullPath = Path.GetFullPath(options.FileSpec);
								if (Path.HasExtension(fullPath) && !fullPath.Contains('*') && !fullPath.Contains('?')) {
									// Complete path with filename
									options.Path = Path.GetDirectoryName(fullPath) ?? Directory.GetCurrentDirectory();
									options.FileSpec = Path.GetFileName(fullPath);
								}
								else {
									// Directory path or pattern, extract directory part
									String dir = Path.GetDirectoryName(fullPath) ?? String.Empty;
									if (!String.IsNullOrEmpty(dir)) {
										options.Path = dir;
										options.FileSpec = Path.GetFileName(fullPath);
									}
								}
							}
						}
						catch (Exception ex) {
							LogFinding($"Error processing filespec argument '{fileSpecArg}': {ex.Message}", LogLevel.Error);
							// Keep default filespec
							LogFinding($"Using default file specification: {options.FileSpec}", LogLevel.Warning);
						}
					}
					else if (arg == "--verbose" || arg == "-v" || arg == "--verboseoutput") {
						options.VerboseOutput = true;

						// Skip any "true" or "false" that might follow (treat as separate arg)
						if (i + 1 < args.Length) {
							String boolValue = args[i + 1].ToLowerInvariant();
							if (boolValue == "true" || boolValue == "false") {
								options.VerboseOutput = boolValue == "true";
								i++; // Skip the value in next iteration
							}
						}
					}
					else if ((arg == "--logfile" || arg == "-l") && i + 1 < args.Length) {
						i++;
						options.LogFile = args[i];
					}
					else if (arg == "--continue" || arg == "-c") {
						options.ContinueOnErrors = true;

						// Skip any "true" or "false" that might follow (treat as separate arg)
						if (i + 1 < args.Length) {
							String boolValue = args[i + 1].ToLowerInvariant();
							if (boolValue == "true" || boolValue == "false") {
								options.ContinueOnErrors = boolValue == "true";
								i++; // Skip the value in next iteration
							}
						}
					}
					else {
						Console.WriteLine($"Warning: Unknown argument '{args[i]}' ignored.");
					}
				}

				// Add final validation
				if (!options.FileSpec.Contains('*') && !options.FileSpec.Contains('?') &&
						!options.FileSpec.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase)) {
					try {
						if (Directory.Exists(Path.Combine(options.Path, options.FileSpec))) {
							// If filespec is actually a directory
							options.Path = Path.Combine(options.Path, options.FileSpec);
							options.FileSpec = "*.lnk";
						}
						else if (!options.FileSpec.Contains('.')) {
							// No extension specified, default to .lnk
							options.FileSpec += ".lnk";
						}
					}
					catch (Exception ex) {
						LogFinding($"Error during path validation: {ex.Message}", LogLevel.Error);
						// Keep existing values
					}
				}

				// Ensure path is absolute
				try {
					options.Path = Path.GetFullPath(options.Path);
				}
				catch (Exception ex) {
					LogFinding($"Error resolving absolute path: {ex.Message}", LogLevel.Error);
					options.Path = Directory.GetCurrentDirectory();
				}
			}
			catch (Exception ex) {
				LogFinding($"Error parsing command line arguments: {ex.Message}", LogLevel.Critical);
				options.Path = Directory.GetCurrentDirectory();
				options.FileSpec = "*.lnk";
			}

			LogFinding($"Configured Path: {options.Path}", LogLevel.Info);
			LogFinding($"Configured FileSpec: {options.FileSpec}", LogLevel.Info);
			LogFinding($"Configured Recurse: {options.Recurse}", LogLevel.Info);
			LogFinding($"Configured VerboseOutput: {options.VerboseOutput}", LogLevel.Info);
			LogFinding($"Configured LogFile: {options.LogFile}", LogLevel.Info);
			LogFinding($"Configured ContinueOnErrors: {options.ContinueOnErrors}", LogLevel.Info);

			return options;
		}

		/// <summary>
		/// Performs forensic analysis of a LNK file with comprehensive exception handling
		/// Checks for potential exploitation attempts and suspicious patterns
		/// </summary>
		/// <param name="lnkPath">Path to LNK file</param>
		/// <returns>Forensic analysis results</returns>
		private static ForensicResult AnalyzeLnkFileForEvasion(String lnkPath) {
			ForensicResult result = new ForensicResult {
				FilePath = lnkPath,
				AnalysisTime = DateTime.UtcNow
			};

			IShellLink? link = null;
			IPersistFile? file = null;

			try {
				// Validate file exists
				if (!File.Exists(lnkPath)) {
					result.AnalysisSucceeded = false;
					result.ErrorMessage = "File does not exist";
					result.Findings.Add("Error: File does not exist");
					LogFinding($"File not found: {lnkPath}", LogLevel.Error);
					return result;
				}

				// Get basic file information even if LNK analysis fails
				SafeGetFileInfo(lnkPath, result);

				// Check if file is readable
				try {
					using (FileStream fs = File.Open(lnkPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite)) {
						// Just testing if we can open the file
					}
				}
				catch (Exception ex) {
					result.AnalysisSucceeded = false;
					result.ErrorMessage = $"Cannot read file: {ex.Message}";
					result.Findings.Add($"Error: Cannot read file: {ex.Message}");
					LogFinding($"Cannot read file {lnkPath}: {ex.Message}", LogLevel.Error);
					return result;
				}

				// Check if file is really a LNK file
				Boolean isLnkFile = false;
				try {
					// Check for LNK file signature (first 4 bytes are 4C 00 00 00)
					using (FileStream fs = File.Open(lnkPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite)) {
						if (fs.Length >= 4) {
							Byte[] header = new Byte[4];
							Int32 bytesRead = fs.Read(header, 0, 4);
							isLnkFile = bytesRead == 4 && header[0] == 0x4c && header[1] == 0x00 &&
												 header[2] == 0x00 && header[3] == 0x00;
						}
					}

					if (!isLnkFile) {
						LogFinding($"Warning: File does not appear to be a valid .LNK file: {lnkPath}", LogLevel.Warning);
						result.Findings.Add("Warning: File does not have a valid .LNK signature");
						// Continue analysis anyway, but warn the user
					}
				}
				catch (Exception ex) {
					LogFinding($"Error checking file signature: {ex.Message}", LogLevel.Warning);
					// Continue analysis anyway
				}

				//// Create COM objects for LNK analysis
				//try {
				//	link = (IShellLink)new ShellLink();
				//	file = (IPersistFile)link;
				//}
				//catch (Exception ex) {
				//	result.AnalysisSucceeded = false;
				//	result.ErrorMessage = $"Failed to create COM objects: {ex.Message}";
				//	result.Findings.Add($"Error: COM initialization failed: {ex.Message}");
				//	LogFinding($"COM initialization failed for {lnkPath}: {ex.Message}", LogLevel.Error);
				//	return result;
				//}

				// Create COM objects for LNK analysis
				try {
					// Try to create the COM objects
					try {
						link = (IShellLink)(new ShellLink());
						if (link == null) {
							throw new NullReferenceException("Failed to create ShellLink COM object - returned null");
						}
					}
					catch (Exception ex) {
						result.AnalysisSucceeded = false;
						result.ErrorMessage = $"Failed to create ShellLink COM object: {ex.Message}";
						result.Findings.Add($"Error: COM initialization failed: {ex.Message}");
						LogFinding($"COM initialization failed for {lnkPath}: {ex.Message}", LogLevel.Error);
						return result;
					}

					// Now try to get the IPersistFile interface
					try {
						file = (IPersistFile)link;
						if (file == null) {
							throw new NullReferenceException("Failed to acquire IPersistFile interface - returned null");
						}
					}
					catch (Exception ex) {
						result.AnalysisSucceeded = false;
						result.ErrorMessage = $"Failed to get IPersistFile interface: {ex.Message}";
						result.Findings.Add($"Error: COM interface acquisition failed: {ex.Message}");
						LogFinding($"COM interface acquisition failed for {lnkPath}: {ex.Message}", LogLevel.Error);
						return result;
					}
				}
				catch (Exception ex) {
					result.AnalysisSucceeded = false;
					result.ErrorMessage = $"Failed to create COM objects: {ex.Message}";
					result.Findings.Add($"Error: COM initialization failed: {ex.Message}");
					LogFinding($"COM initialization failed for {lnkPath}: {ex.Message}", LogLevel.Error);
					return result;
				}

				// Load the LNK file
				try {
					if (file == null) {
						throw new NullReferenceException("IPersistFile is null");
					}

					file.Load(lnkPath, 0);
				}
				catch (COMException ex) {
					result.AnalysisSucceeded = false;
					result.ErrorMessage = $"COM error loading file: {ex.Message} (HRESULT: 0x{ex.HResult:X8})";
					result.Findings.Add($"Error: Failed to load LNK file: {ex.Message}");
					LogFinding($"COM error loading {lnkPath}: {ex.Message} (HRESULT: 0x{ex.HResult:X8})", LogLevel.Error);
					return result;
				}
				catch (Exception ex) {
					result.AnalysisSucceeded = false;
					result.ErrorMessage = $"Failed to load file: {ex.Message}";
					result.Findings.Add($"Error: Failed to load LNK file: {ex.Message}");
					LogFinding($"Error loading {lnkPath}: {ex.Message}", LogLevel.Error);
					return result;
				}

				//// Load the LNK file
				//try {
				//	file.Load(lnkPath, 0);
				//}
				//catch (COMException ex) {
				//	result.AnalysisSucceeded = false;
				//	result.ErrorMessage = $"COM error loading file: {ex.Message} (HRESULT: 0x{ex.HResult:X8})";
				//	result.Findings.Add($"Error: Failed to load LNK file: {ex.Message}");
				//	LogFinding($"COM error loading {lnkPath}: {ex.Message} (HRESULT: 0x{ex.HResult:X8})", LogLevel.Error);
				//	return result;
				//}
				//catch (Exception ex) {
				//	result.AnalysisSucceeded = false;
				//	result.ErrorMessage = $"Failed to load file: {ex.Message}";
				//	result.Findings.Add($"Error: Failed to load LNK file: {ex.Message}");
				//	LogFinding($"Error loading {lnkPath}: {ex.Message}", LogLevel.Error);
				//	return result;
				//}

				// Extract LNK file properties with exception handling for each property
				StringBuilder targetPath = new StringBuilder(260);
				StringBuilder arguments = new StringBuilder(260);
				StringBuilder workingDir = new StringBuilder(260);
				StringBuilder description = new StringBuilder(1024);

				//// Extract target path
				//try {
				//	link.GetPath(targetPath, targetPath.Capacity, out IntPtr _, 0);
				//	result.Metadata.Add("Target", targetPath.ToString());
				//}
				//catch (Exception ex) {
				//	LogFinding($"Error extracting target path: {ex.Message}", LogLevel.Warning);
				//	result.Metadata.Add("Target", $"Error: {ex.Message}");
				//}

				// Create a properly initialized WIN32_FIND_DATAW structure
				WIN32_FIND_DATAW findData = new WIN32_FIND_DATAW();

				// Extract target path
				try {
					StringBuilder newTargetPath = new StringBuilder(260); // MAX_PATH
					link.GetPath(newTargetPath, targetPath.Capacity, ref findData, 0);
					result.Metadata.Add("Target", newTargetPath.ToString());
				}
				catch (Exception ex) {
					LogFinding($"Error extracting target path: {ex.Message}", LogLevel.Warning);
					result.Metadata.Add("Target", $"Error: {ex.Message}");
				}

				// Extract arguments
				try {
					link.GetArguments(arguments, arguments.Capacity);
					result.Metadata.Add("Arguments", arguments.ToString());
				}
				catch (Exception ex) {
					LogFinding($"Error extracting arguments: {ex.Message}", LogLevel.Warning);
					result.Metadata.Add("Arguments", $"Error: {ex.Message}");
				}

				// Extract working directory
				try {
					link.GetWorkingDirectory(workingDir, workingDir.Capacity);
					result.Metadata.Add("WorkingDir", workingDir.ToString());
				}
				catch (Exception ex) {
					LogFinding($"Error extracting working directory: {ex.Message}", LogLevel.Warning);
					result.Metadata.Add("WorkingDir", $"Error: {ex.Message}");
				}

				// Extract description
				try {
					link.GetDescription(description, description.Capacity);
					result.Metadata.Add("Description", description.ToString());
				}
				catch (Exception ex) {
					LogFinding($"Error extracting description: {ex.Message}", LogLevel.Warning);
					result.Metadata.Add("Description", $"Error: {ex.Message}");
				}


				// Analyze found properties
				if (!String.IsNullOrEmpty(targetPath.ToString()) && result != null) {
					AnalyzePathForEvasion(targetPath.ToString(), result);
				}

				if (!String.IsNullOrEmpty(arguments.ToString()) && result != null) {
					AnalyzeArgumentsForEvasion(arguments.ToString(), result);
				}

				if (!String.IsNullOrEmpty(workingDir.ToString()) && result != null) {
					AnalyzePathForEvasion(workingDir.ToString(), result, "WorkingDir");
				}

				//// Analyze found properties
				//if (!String.IsNullOrEmpty(targetPath.ToString())) {
				//	AnalyzePathForEvasion(targetPath.ToString(), result);
				//}

				//if (!String.IsNullOrEmpty(arguments.ToString())) {
				//	AnalyzeArgumentsForEvasion(arguments.ToString(), result);
				//}

				//if (!String.IsNullOrEmpty(workingDir.ToString())) {
				//	AnalyzePathForEvasion(workingDir.ToString(), result, "WorkingDir");
				//}

				return result;
			}
			catch (Exception ex) {
				LogFinding($"Error analyzing {lnkPath}: {ex.Message}", LogLevel.Error);
				result.AnalysisSucceeded = false;
				result.ErrorMessage = ex.Message;
				result.Findings.Add($"Analysis Error: {ex.Message}");
				if (ex.InnerException != null) {
					result.Findings.Add($"Inner Error: {ex.InnerException.Message}");
				}
				TotalErrorCount++;
				return result;
			}
			finally {
				try {
					if (file != null)
						Marshal.ReleaseComObject(file);
					if (link != null)
						Marshal.ReleaseComObject(link);
				}
				catch (Exception ex) {
					LogFinding($"Error releasing COM objects: {ex.Message}", LogLevel.Warning);
				}
			}
		}

		/// <summary>
		/// Analyzes a path for potential evasion techniques with enhanced error handling
		/// </summary>
		/// <param name="path">Path to analyze</param>
		/// <param name="result">Results container</param>
		/// <param name="context">Context label for findings</param>
		private static void AnalyzePathForEvasion(String path, ForensicResult result, String context = "Path") {
			try {
				// Guard against null result
				if (result == null) {
					LogFinding($"Error: ForensicResult was null when analyzing path for {context}", LogLevel.Error);
					return;
				}

				if (String.IsNullOrEmpty(path)) {
					result.Findings.Add($"{context}: Empty or null path detected");
					return;
				}

				// Check for whitespace padding
				try {
					Int32 leadingWhitespace = path.TakeWhile(c => SuspiciousWhitespace.Contains((Byte)c)).Count();
					Int32 trailingWhitespace = path.Reverse().TakeWhile(c => SuspiciousWhitespace.Contains((Byte)c)).Count();

					if (leadingWhitespace > 0 || trailingWhitespace > 0) {
						result.HasSuspiciousIndicators = true;
						result.Findings.Add($"{context}: Suspicious whitespace padding detected - Leading: {leadingWhitespace}, Trailing: {trailingWhitespace}");
					}
				}
				catch (Exception ex) {
					LogFinding($"Error analyzing whitespace padding: {ex.Message}", LogLevel.Warning);
				}

				// Check for suspicious characters
				try {
					IEnumerable<String> suspiciousChars = path.Where(c => c < 32 || c > 126).Select(c => $"0x{(Byte)c:X2}");
					if (suspiciousChars.Any()) {
						result.HasSuspiciousIndicators = true;
						result.Findings.Add($"{context}: Contains suspicious characters: {String.Join(", ", suspiciousChars)}");
					}
				}
				catch (Exception ex) {
					LogFinding($"Error analyzing suspicious characters: {ex.Message}", LogLevel.Warning);
				}

				// Check for environment variables
				try {
					if (path.Contains('%')) {
						result.Findings.Add($"{context}: Contains environment variables");
					}
				}
				catch (Exception ex) {
					LogFinding($"Error checking for environment variables: {ex.Message}", LogLevel.Warning);
				}

				// Check for path traversal
				try {
					if (path.Contains("..")) {
						result.Findings.Add($"{context}: Contains path traversal sequences (..)");
						result.HasSuspiciousIndicators = true;
					}
				}
				catch (Exception ex) {
					LogFinding($"Error checking for path traversal: {ex.Message}", LogLevel.Warning);
				}
			}
			catch (Exception ex) {
				LogFinding($"Error in AnalyzePathForEvasion: {ex.Message}", LogLevel.Error);
				result.Findings.Add($"{context}: Analysis error: {ex.Message}");
			}
		}

		/// <summary>
		/// Analyzes command arguments for potential injection attempts
		/// with robust error handling to prevent failures
		/// </summary>
		/// <param name="arguments">Arguments to analyze</param>
		/// <param name="result">Results container</param>
		private static void AnalyzeArgumentsForEvasion(String arguments, ForensicResult result) {
			try {
				// Guard against null result
				if (result == null) {
					LogFinding("Error: ForensicResult was null when analyzing arguments", LogLevel.Error);
					return;
				}

				if (String.IsNullOrEmpty(arguments)) {
					return;
				}

				// Check for command injection characters
				try {
					String[] suspiciousPatterns = [
							"&", "&&", "|", "||", ";", "`",
												"$", "(", ")", "{", "}", "<", ">"
					];

					foreach (String pattern in suspiciousPatterns) {
						if (arguments.Contains(pattern)) {
							result.HasSuspiciousIndicators = true;
							result.Findings.Add($"Arguments: Potential command injection character detected: {pattern}");
						}
					}
				}
				catch (Exception ex) {
					LogFinding($"Error checking for suspicious patterns: {ex.Message}", LogLevel.Warning);
				}

				// Check for encoded or escaped characters
				try {
					if (arguments.Contains('%') || arguments.Contains('\\')) {
						result.Findings.Add("Arguments: Contains encoded or escaped characters");
					}
				}
				catch (Exception ex) {
					LogFinding($"Error checking for encoded characters: {ex.Message}", LogLevel.Warning);
				}

				// Analyze whitespace usage
				try {
					IEnumerable<CharacterCountInfo> whitespaceAnalysis = arguments
							.GroupBy(c => c)
							.Where(g => SuspiciousWhitespace.Contains((Byte)g.Key))
							.Select(g => new CharacterCountInfo { Character = g.Key, Count = g.Count() });

					foreach (CharacterCountInfo info in whitespaceAnalysis) {
						result.Findings.Add($"Arguments: Contains {info.Count} instances of whitespace character 0x{(Byte)info.Character:X2}");
					}
				}
				catch (Exception ex) {
					LogFinding($"Error analyzing whitespace: {ex.Message}", LogLevel.Warning);
				}

				// Check for PowerShell specific patterns
				try {
					String lowerArgs = arguments.ToLowerInvariant();
					if (lowerArgs.Contains("powershell") || lowerArgs.Contains("-encodedcommand") ||
							lowerArgs.Contains("-windowstyle hidden") || lowerArgs.Contains("-noprofile")) {
						result.HasSuspiciousIndicators = true;
						result.Findings.Add("Arguments: Contains PowerShell execution patterns");
					}
				}
				catch (Exception ex) {
					LogFinding($"Error checking for PowerShell patterns: {ex.Message}", LogLevel.Warning);
				}
			}
			catch (Exception ex) {
				LogFinding($"Error in AnalyzeArgumentsForEvasion: {ex.Message}", LogLevel.Error);
				result.Findings.Add($"Arguments: Analysis error: {ex.Message}");
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
    --path, -p <directory> : Directory to scan (default: current directory)
                           (Can also be a full path to a .LNK file)
    --recurse, -r [true|false] : Scan subdirectories recursively (default: false)
    --filespec, -f <pat>   : File specification (default: *.lnk)
    --verbose, -v [true|false] : Enable verbose output
    --logfile, -l <file>   : Custom log file path (default: lnk_analysis.log)
    --continue, -c [true|false] : Continue on errors (default: true)
    --help, -h, -?         : Show this help message
 
Examples:
    LnkFileAnalyzer.exe --path C:\Users --recurse
    LnkFileAnalyzer.exe --path C:\Users\*.lnk --recurse true
    LnkFileAnalyzer.exe --path D:\Suspicious\test.lnk
    LnkFileAnalyzer.exe -p C:\Users\Desktop -f test*.lnk -v");
		}

		/// <summary>
		/// Main entry point for LNK file analysis with improved error handling
		/// </summary>
		/// <param name="args">Command line arguments</param>
		public static void Main(String[] args) {
			try {
				// Display banner
				Console.WriteLine("LNK File Analyzer v1.2 - Windows Shortcut File (.LNK) Security Analyzer");
				Console.WriteLine("Copyright © 2025 - Created for forensic security investigations");
				Console.WriteLine();

				AnalyzerOptions options;

				try {
					options = ParseCommandLineArgs(args);
				}
				catch (Exception ex) {
					LogFinding($"Critical error parsing arguments: {ex.Message}", LogLevel.Critical);
					Console.WriteLine("\nRun with --help for usage information.");
					return;
				}

				if (options.ShowHelp) {
					ShowHelp();
					return;
				}

				// Initialize metrics
				Int32 filesAnalyzed = 0;
				Int32 filesWithErrors = 0;
				Int32 suspiciousFiles = 0;
				Stopwatch totalTime = new Stopwatch();
				totalTime.Start();

				LogFinding($"Starting analysis with path: {options.Path}", LogLevel.Info);
				LogFinding($"Recursive search: {options.Recurse}", LogLevel.Info);
				LogFinding($"File specification: {options.FileSpec}", LogLevel.Info);

				String[] files;
				try {
					files = Directory.GetFiles(
							options.Path,
							options.FileSpec,
							options.Recurse ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly
					);
				}
				catch (Exception ex) {
					LogFinding($"Error getting files: {ex.Message}", LogLevel.Critical);
					return;
				}

				if (files.Length == 0) {
					LogFinding("No matching files found.", LogLevel.Warning);
					return;
				}

				LogFinding($"Found {files.Length} files to analyze.", LogLevel.Info);

				List<ForensicResult> results = new List<ForensicResult>();

				foreach (String file in files) {
					try {
						LogFinding($"Analyzing: {file}", LogLevel.Info);
						Stopwatch fileTime = new Stopwatch();
						fileTime.Start();

						ForensicResult result = AnalyzeLnkFileForEvasion(file);
						results.Add(result);

						fileTime.Stop();
						filesAnalyzed++;

						if (!result.AnalysisSucceeded) {
							filesWithErrors++;
						}

						if (options.VerboseOutput) {
							LogFinding($"Analysis completed in {fileTime.ElapsedMilliseconds}ms", LogLevel.Info);
						}
					}
					catch (Exception ex) {
						LogFinding($"Error processing file {file}: {ex.Message}", LogLevel.Error);
						filesWithErrors++;

						if (!options.ContinueOnErrors) {
							LogFinding("Stopping analysis due to error (use --continue to override)", LogLevel.Critical);
							break;
						}
					}
				}

				totalTime.Stop();

				List<ForensicResult> suspicious = results.Where(r => r.HasSuspiciousIndicators).ToList();
				List<ForensicResult> errors = results.Where(r => !r.AnalysisSucceeded).ToList();
				suspiciousFiles = suspicious.Count;

				// Generate summary report
				Console.WriteLine("\n=== Analysis Summary ===");
				Console.WriteLine($"Total files found: {files.Length}");
				Console.WriteLine($"Files analyzed: {filesAnalyzed}");
				Console.WriteLine($"Suspicious files detected: {suspicious.Count}");
				Console.WriteLine($"Files with errors: {filesWithErrors}");
				Console.WriteLine($"Total analysis time: {totalTime.ElapsedMilliseconds}ms");

				if (suspicious.Count != 0) {
					Console.WriteLine("\n=== Suspicious Files ===");
					foreach (ForensicResult result in suspicious) {
						Console.WriteLine($"\nFile: {result.FilePath}");
						foreach (String finding in result.Findings) {
							Console.WriteLine($"  - {finding}");
						}
					}
				}

				if (filesWithErrors > 0 && options.VerboseOutput) {
					Console.WriteLine("\n=== Files With Errors ===");
					foreach (ForensicResult result in errors) {
						Console.WriteLine($"\nFile: {result.FilePath}");
						Console.WriteLine($"Error: {result.ErrorMessage}");
					}
				}

				try {
					File.WriteAllLines(options.LogFile, ForensicLog);
					Console.WriteLine($"\nDetailed analysis log saved to: {options.LogFile}");
				}
				catch (Exception ex) {
					Console.WriteLine($"\nError saving log file: {ex.Message}");
				}

				// Set exit code based on findings
				if (suspicious.Count > 0) {
					Environment.ExitCode = 2;  // Suspicious files found
				}
				else if (filesWithErrors > 0) {
					Environment.ExitCode = 1;  // Errors occurred
				}
				else {
					Environment.ExitCode = 0;  // No issues
				}
			}
			catch (Exception ex) {
				LogFinding($"Critical error: {ex.Message}", LogLevel.Critical);
				LogFinding(ex.StackTrace ?? "No stack trace available", LogLevel.Error);
				Environment.ExitCode = -1;
			}
		}
	}
}



