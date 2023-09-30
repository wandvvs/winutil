/*

	


 ▄█     █▄   ▄█  ███▄▄▄▄   ████████▄   ▄██████▄   ▄█     █▄     ▄████████      ███    █▄      ███      ▄█   ▄█        ▄█      ███     ▄██   ▄
███     ███ ███  ███▀▀▀██▄ ███   ▀███ ███    ███ ███     ███   ███    ███      ███    ███ ▀█████████▄ ███  ███       ███  ▀█████████▄ ███   ██▄
███     ███ ███▌ ███   ███ ███    ███ ███    ███ ███     ███   ███    █▀       ███    ███    ▀███▀▀██ ███▌ ███       ███▌    ▀███▀▀██ ███▄▄▄███
███     ███ ███▌ ███   ███ ███    ███ ███    ███ ███     ███   ███             ███    ███     ███   ▀ ███▌ ███       ███▌     ███   ▀ ▀▀▀▀▀▀███
███     ███ ███▌ ███   ███ ███    ███ ███    ███ ███     ███ ▀███████████      ███    ███     ███     ███▌ ███       ███▌     ███     ▄██   ███
███     ███ ███  ███   ███ ███    ███ ███    ███ ███     ███          ███      ███    ███     ███     ███  ███       ███      ███     ███   ███
███ ▄█▄ ███ ███  ███   ███ ███   ▄███ ███    ███ ███ ▄█▄ ███    ▄█    ███      ███    ███     ███     ███  ███▌    ▄ ███      ███     ███   ███
 ▀███▀███▀  █▀    ▀█   █▀  ████████▀   ▀██████▀   ▀███▀███▀   ▄████████▀       ████████▀     ▄████▀   █▀   █████▄▄██ █▀      ▄████▀    ▀█████▀
																										   ▀




Make sure that multibyte encoding support is enabled in your visual studio project properties
*/
#include <Windows.h>
#include <tlhelp32.h>
#include <fstream>
#include <iostream>
#include <winternl.h>
#include <string>
#include <ShlObj.h>
#include <Shlwapi.h>
#include <Shellapi.h>
#include <thread>
#include <chrono>
#include <vector>
#include <locale>
#include <iomanip>
#include <stdexcept>
#include <string>
#include <winternl.h>
#include <Psapi.h>
#include <Aclapi.h>

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Winmm.lib")
#pragma warning(disable : 4996)

/**
 * Enumeration for MessageBox Types.
 *
 * This enum defines different types of messages that can be displayed using the MessageBox.
 * It is used to specify the type of message box and the corresponding icon to display.
 */
enum MessageBoxType {
	INFORMATION, ///< Informational message with an information icon.
	QUESTION,    ///< Question message with a question mark icon.
	WARNING,     ///< Warning message with a warning icon.
	MISTAKE      ///< Error message with an error icon.
};

/**
 * Custom Windows Exception Class.
 *
 * This class is used to create custom exceptions for Windows-specific errors.
 * It inherits from std::runtime_error and includes additional information about
 * the Windows error code associated with the exception.
 */
class WinException : public std::runtime_error {
public:
	/**
	 * Constructor for WinException.
	 *
	 * @param message A string containing a custom error message.
	 * @remarks The constructor appends the Windows error code to the provided message.
	 */
	WinException(const std::string& message) : std::runtime_error(message) {
		errorMsg = message + "\nError code: " + std::to_string(GetLastError());
	}

	/**
	 * Retrieve the exception message.
	 *
	 * @return A C-string containing the error message along with the associated
	 *         Windows error code.
	 */
	const char* what() const noexcept override {
		return errorMsg.c_str();
	}
private:
	std::string errorMsg; ///< The error message including the Windows error code.
};

class WinUtil {
public:

	/**
		 * Shutdown or restart the computer.
		 *
		 * This method initiates a system shutdown or restart based on the provided parameter.
		 *
		 * @param rebootAfterShutdown If `rebootAfterShutdown` is set to TRUE, the method initiates a system restart; if FALSE, it initiates a system shutdown.
		 *
		 * @return TRUE if the system shutdown or restart was successfully initiated, FALSE otherwise.
		 *
		 * @throws WinException if an error occurs while opening the process token, looking up privilege values, adjusting token privileges,
		 *                      or initiating the system shutdown.
		 *
		 * @note To perform a system shutdown or restart, this method requires appropriate privileges.
		 *       It adjusts the token privileges to enable shutdown/restart capabilities, initiates the action,
		 *       and then reverts the privileges to their original state before returning.
		 *       If any step of this process fails, it throws a WinException with an appropriate error message.
	*/
	static BOOL shutdown(BOOL rebootAfterShutdown) {
		HANDLE hToken;
		TOKEN_PRIVILEGES tkp;

		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
			throw WinException("Failed to open process token");
		}

		if (!LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid)) {
			CloseHandle(hToken);
			throw WinException("Failed to lookup privilege value");
		}

		tkp.PrivilegeCount = 1;
		tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0)) {
			CloseHandle(hToken);
			throw WinException("Failed to adjust token privileges");
		}

		if (!InitiateSystemShutdownA(NULL, NULL, 0, TRUE, rebootAfterShutdown)) {
			CloseHandle(hToken);
			throw WinException("Failed to initiate system shutdown");
		}

		tkp.Privileges[0].Attributes = 0;

		if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0)) {
			CloseHandle(hToken);
			throw WinException("Failed to adjust token privileges");
		}

		CloseHandle(hToken);

		return TRUE;
	}

	/**
		 * Get the Process ID (PID) of a process by its name.
		 *
		 * This method attempts to find and return the Process ID (PID) of a process with the specified name.
		 * It uses the CreateToolhelp32Snapshot and Process32First/Process32Next functions to enumerate the running processes
		 * and matches the process name to the specified name. If a matching process is found, its PID is returned;
		 * if the process is not found, it throws a WinException with an error message and returns 0.
		 *
		 * @param processName The name of the process for which to retrieve the PID.
		 *
		 * @return The Process ID (PID) of the specified process, or 0 if the process is not found.
		 *
		 * @throws WinException if an error occurs during the process enumeration or if the specified process is not found.
		 *
		 * @note This method scans the list of running processes to find a match by name. If a process with the specified name is found,
		 *       its PID is returned; otherwise, it throws a WinException with an appropriate error message.
	*/
	static DWORD getProcessId(const char* processName) {
		DWORD pid = 0;
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (snapshot != INVALID_HANDLE_VALUE) {
			PROCESSENTRY32 processEntry;
			processEntry.dwSize = sizeof(PROCESSENTRY32);
			if (Process32First(snapshot, &processEntry)) {
				do {
					if (strcmp(processEntry.szExeFile, processName) == 0) {
						pid = processEntry.th32ProcessID;
						break;
					}
				} while (Process32Next(snapshot, &processEntry));
			}
		}

		if (pid == 0) {
			throw WinException("Process " + std::string(processName) + " not found");
		}
		return pid;
	}

	/**
		 * Terminate a process by its name.
		 *
		 * This method attempts to terminate a process with the specified name by obtaining its Process ID (PID)
		 * and terminating the process using the TerminateProcess function.
		 * If the process is successfully terminated, it returns 1; if the process is not found, it throws a WinException with an error message;
		 * if any other error occurs, it throws a WinException and returns -1.
		 *
		 * @param processName The name of the process to be terminated.
		 *
		 * @return 1 if the process was successfully terminated, -1 if there was an error, or an exception is thrown for process not found.
		 *
		 * @throws WinException if an error occurs during the process termination or if the specified process is not found.
		 *
		 * @note This method uses the getProcessId function to obtain the Process ID (PID) of the specified process by name.
		 *       It then attempts to open the process using OpenProcess and terminates it using TerminateProcess.
		 *       If the process is not found or if any other error occurs, it throws a WinException with an appropriate error message.
	*/
	static INT killProcess(const char* processName) {
		DWORD pid = getProcessId(processName);

		if (pid == 0) {
			throw WinException("Process " + std::string(processName) + " not found");
		}
		else {
			HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
			if (handle != NULL) {
				TerminateProcess(handle, 0);
				return 1;
				CloseHandle(handle);
			}
			else {
				throw WinException("Failed to open process");

				return -1;
			}
		}
	}

	/**
		 * Get a handle to a process by its Process ID (PID).
		 *
		 * This method attempts to obtain a handle to a process with the specified Process ID (PID).
		 * If a valid handle to the process is obtained, it returns TRUE; otherwise, it throws a WinException with an error message
		 * and returns FALSE to indicate a failure to get the process handle.
		 *
		 * @param handleToProcess A pointer to a handle that will store the obtained process handle.
		 * @param pid The Process ID (PID) of the target process.
		 *
		 * @return TRUE if the process handle was successfully obtained; FALSE otherwise.
		 *
		 * @throws WinException if an error occurs during the process handle retrieval.
		 *
		 * @note This method uses the OpenProcess function from the Windows API to obtain a handle to the specified process by its PID.
		 *       If the process handle cannot be obtained for any reason, it throws a WinException with an error message.
	*/
	static BOOL getProcess(HANDLE* handleToProcess, DWORD pid) {
		*handleToProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);

		if (*handleToProcess == NULL) {
			throw WinException("Failed to get process with " + std::string(std::to_string(pid)) + " pid");

			return FALSE;
		}
		return TRUE;
	}

	/**
		 * Close a handle to a process or resource.
		 *
		 * This method attempts to close a handle to a process or resource specified by the provided handle pointer.
		 * If the handle is successfully closed, it returns TRUE; otherwise, it throws a WinException with an error message
		 * and returns FALSE to indicate a failure to close the handle.
		 *
		 * @param handleToProcess A pointer to the handle to be closed.
		 *
		 * @return TRUE if the handle was successfully closed; FALSE otherwise.
		 *
		 * @throws WinException if an error occurs during the handle closing process.
		 *
		 * @note This method checks if the handle is not NULL and attempts to close it using the CloseHandle function from the Windows API.
		 *       If the handle cannot be closed for any reason, it throws a WinException with an error message.
	*/
	static BOOL closeHandle(HANDLE* handleToProcess) {
		if (*handleToProcess != NULL && !CloseHandle(*handleToProcess)) {
			throw WinException("Failed to close handle");
			return FALSE;
		}

		*handleToProcess = nullptr;

		return TRUE;
	}


	/**
		 * Open a file at the specified path using the default associated program.
		 *
		 * This method attempts to open a file located at the specified path using the default associated program.
		 * If the file can be successfully opened, it returns TRUE; otherwise, it throws a WinException with an error message
		 * and returns FALSE to indicate a failure to open the file.
		 *
		 * @param path The path of the file to be opened.
		 *
		 * @return TRUE if the file was successfully opened; FALSE otherwise.
		 *
		 * @throws WinException if an error occurs during the file opening process.
		 *
		 * @note This method uses the ShellExecute function from the Windows API to open the specified file using the default program.
		 *       If the file cannot be opened for any reason, it throws a WinException with an error message.
	*/
	static BOOL openFile(const char* path) {
		HINSTANCE result = ShellExecute(NULL, "open", path, NULL, NULL, SW_SHOWNORMAL);

		if ((intptr_t)result <= 32) {
			throw WinException("Failed to open file by path");

			return false;
		}

		return true;
	}

	/**
		 * Create a new directory at the specified path.
		 *
		 * This method attempts to create a new directory at the specified path.
		 * If the directory creation is successful, it returns TRUE; otherwise, it throws a WinException with an error message
		 * and returns FALSE to indicate a failure to create the directory.
		 *
		 * @param path The path where the new directory will be created.
		 *
		 * @return TRUE if the directory was successfully created; FALSE otherwise.
		 *
		 * @throws WinException if an error occurs during the directory creation process.
		 *
		 * @note This method uses the CreateDirectory function from the Windows API to create a new directory at the specified path.
		 *       If the directory cannot be created for any reason, it throws a WinException with an error message.
	*/
	static BOOL createDirectory(const char* path) {
		if (CreateDirectory(path, NULL) == FALSE) {
			throw WinException("Failed to create directory");
			return FALSE;
		}

		return TRUE;
	}

	/**
		 * Create a new file at the specified path.
		 *
		 * This method attempts to create a new file at the specified path.
		 * If the file creation is successful, it returns TRUE; otherwise, it throws a WinException with an error message
		 * and returns FALSE to indicate a failure to create the file.
		 *
		 * @param path The path where the new file will be created.
		 *
		 * @return TRUE if the file was successfully created; FALSE otherwise.
		 *
		 * @throws WinException if an error occurs during the file creation process.
		 *
		 * @note This method uses the CreateFileA function from the Windows API to create a new file at the specified path.
		 *       If the file cannot be created for any reason, it throws a WinException with an error message.
	*/
	static BOOL createFile(const char* path) {
		HANDLE hFile = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

		if (hFile == INVALID_HANDLE_VALUE) {
			throw WinException("Failed to create file by path");

			return false;
		}

		CloseHandle(hFile);
		return true;
	}

	/**
		 * Move a file or directory from the specified path to a new destination path.
		 *
		 * This method attempts to move a file or directory located at the specified path to a new destination path.
		 * If the move operation is successful, it returns TRUE; otherwise, it throws a WinException with an error message
		 * and returns FALSE to indicate a failure to move the file or directory.
		 *
		 * @param path The current path of the file or directory to be moved.
		 * @param newPath The new destination path for the file or directory.
		 *
		 * @return TRUE if the file or directory was successfully moved; FALSE otherwise.
		 *
		 * @throws WinException if an error occurs during the move operation.
		 *
		 * @note This method uses the MoveFile function from the Windows API to move the file or directory to the new path.
		 *       If the move operation cannot be completed for any reason, it throws a WinException with an error message.
	*/
	static BOOL moveFiles(const char* path, const char* newPath) {
		if (MoveFile(path, newPath) == FALSE) {
			throw WinException("Failed to move file by path");

			return false;
		}

		return true;
	}

	/**
		 * Delete a file at the specified path.
		 *
		 * This method attempts to delete a file located at the specified path.
		 * If the deletion is successful, it returns TRUE; otherwise, it throws a WinException with an error message
		 * and returns FALSE to indicate a failure to delete the file.
		 *
		 * @param path The path of the file to be deleted.
		 *
		 * @return TRUE if the file was successfully deleted; FALSE otherwise.
		 *
		 * @throws WinException if an error occurs during the file deletion process.
		 *
		 * @note This method uses the DeleteFile function from the Windows API to delete the specified file.
		 *       If the file cannot be deleted for any reason, it throws a WinException with an error message.
	*/
	static BOOL deleteFile(const char* path) {
		if (DeleteFile(path) == FALSE) {
			throw WinException("Failed to delete file");

			return false;
		}

		return true;
	}

	/**
		 * Delete a directory at the specified path.
		 *
		 * This method attempts to delete a directory located at the specified path.
		 * If the deletion is successful, it returns TRUE; otherwise, it throws a WinException with an error message
		 * and returns FALSE to indicate a failure to delete the directory.
		 *
		 * @param path The path of the directory to be deleted.
		 *
		 * @return TRUE if the directory was successfully deleted; FALSE otherwise.
		 *
		 * @throws WinException if an error occurs during the directory deletion process.
		 *
		 * @note This method uses the RemoveDirectory function from the Windows API to delete the specified directory.
		 *       If the directory cannot be deleted for any reason, it throws a WinException with an error message.
	*/
	static BOOL deleteDirectory(const char* path) {
		if (RemoveDirectory(path) == FALSE) {
			throw WinException("Failed to delete directory");

			return false;
		}

		return true;
	}

	
	/**
		 * Callback function to enumerate and retrieve information about visible windows.
		 *
		 * This callback function is used with the EnumWindows function to enumerate all top-level windows
		 * and retrieve information about visible windows, including their window handles, titles, and associated Process IDs (PIDs).
		 * It is commonly used for window enumeration and information gathering purposes.
		 *
		 * @param hwnd A handle to a top-level window found during enumeration.
		 * @param lParam An application-defined value provided during the EnumWindows call.
		 *
		 * @return TRUE to continue enumeration and processing of windows; FALSE to stop enumeration.
		 *
		 * @note This function checks if a window is visible and retrieves its title and associated PID.
		 *       If a visible window with a title is found, it prints information about the window to the console.
		 *       It is often used with the EnumWindows function to inspect and interact with windows in the system.
	*/
	static BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
		SetConsoleOutputCP(CP_UTF8);
		char buffer[256];
		if (IsWindowVisible(hwnd) && GetWindowTextA(hwnd, buffer, sizeof(buffer)) > 0) {
			DWORD pid;
			GetWindowThreadProcessId(hwnd, &pid);
			std::cout << "Window Handle: " << hwnd << ", Title: " << buffer << ", PID: " << pid << std::endl;
		}
		return TRUE;
	}

	/**
		 * Enumerate and retrieve information about all visible runtime windows on the system.
		 *
		 * This method uses the EnumWindows function to enumerate all top-level windows on the system
		 * and retrieves information about visible windows, including their window handles, titles, and associated Process IDs (PIDs).
		 * It prints the information about each visible window to the console.
		 *
		 * @return None.
		 *
		 * @note This method provides a convenient way to enumerate and gather information about all visible windows
		 *       currently running on the system. It uses the EnumWindowsProc callback function to process each window.
	*/
	static void getAllRuntimeWindows() {
		EnumWindows(EnumWindowsProc, 0);
	}
	typedef NTSTATUS(NTAPI* pdef_NtRaiseHardError)(NTSTATUS ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask OPTIONAL, PULONG_PTR Parameters, ULONG ResponseOption, PULONG Response);
	typedef NTSTATUS(NTAPI* pdef_RtlAdjustPrivilege)(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);

	/**
		 * Trigger a Blue Screen of Death (BSOD) on the Windows system.
		 *
		 * This method triggers a Blue Screen of Death (BSOD) on the Windows system by invoking privileged system calls
		 * to manipulate system privileges and initiate a hard error. This action is for educational purposes only,
		 * and it is not recommended for use on production systems.
		 *
		 * @return TRUE if the BSOD was triggered successfully; FALSE otherwise.
		 *
		 * @note This method performs actions that can lead to a system crash and data loss.
		 *       It should only be used for educational purposes and on non-production systems.
		 *       The method invokes system functions from ntdll.dll to adjust privileges and raise a hard error
		 *       with a specific error status (STATUS_FLOAT_MULTIPLE_FAULTS) that triggers a BSOD.
	*/
	static BOOL getBSOD() {
		BOOLEAN bEnabled;
		ULONG uResp;
		LPVOID lpFuncAddress = GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlAdjustPrivilege");
		LPVOID lpFuncAddress2 = GetProcAddress(GetModuleHandle("ntdll.dll"), "NtRaiseHardError");
		pdef_RtlAdjustPrivilege NtCall = (pdef_RtlAdjustPrivilege)lpFuncAddress;
		pdef_NtRaiseHardError NtCall2 = (pdef_NtRaiseHardError)lpFuncAddress2;
		NTSTATUS NtRet = NtCall(19, TRUE, FALSE, &bEnabled);
		NtCall2(STATUS_FLOAT_MULTIPLE_FAULTS, 0, 0, 0, 6, &uResp);
		return true;
	}
	/**
		 * Retrieve and display information about a specified process by name.
		 *
		 * This method retrieves and displays various information about a process with a given name,
		 * including its Process ID (PID), name, Parent PID, number of threads, base priority, execution flags,
		 * module ID, and delta time.
		 *
		 * @param processName The name of the process for which to retrieve information.
		 *
		 * @return None.
		 *
		 * @throws WinException if an error occurs during the process information retrieval.
		 *
		 * @note This method uses the Windows API functions CreateToolhelp32Snapshot, Process32First, and Process32Next
		 *       to enumerate and retrieve information about running processes.
		 *       If the specified process is found, it displays the relevant information in the console.
		 *       If an error occurs or the process is not found, it throws a WinException with an error message.
	*/
	static void getProcessInfo(const char* processName) {
		DWORD pid = getProcessId(processName);

		if (pid == 0) {
			throw WinException("Failed to get PID of process name");
			return;
		}

		PROCESSENTRY32 processEntry;
		processEntry.dwSize = sizeof(PROCESSENTRY32);

		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

		if (snapshot == INVALID_HANDLE_VALUE) {
			throw WinException("CreateToolhelp32Snapshot failed");
			return;
		}

		if (Process32First(snapshot, &processEntry)) {
			do {
				if (processEntry.th32ProcessID == pid) {
					std::cout << "Process ID: " << processEntry.th32ProcessID << std::endl;
					std::wcout << "Process Name: " << processEntry.szExeFile << std::endl;
					std::cout << "PID: " << processEntry.th32ParentProcessID << std::endl;
					std::cout << "Number of Threads: " << processEntry.cntThreads << std::endl;
					std::cout << "Base Priority: " << processEntry.pcPriClassBase << std::endl;
					std::cout << "Execution Flags: " << processEntry.dwFlags << std::endl;
					std::cout << "Module ID: " << processEntry.th32ModuleID << std::endl;
					std::cout << "Delta Time: " << processEntry.cntUsage << std::endl;
				}
			} while (Process32Next(snapshot, &processEntry));
		}
	}
	/**
		 * Retrieve and display file information for a specified file path.
		 *
		 * This method retrieves and displays various file attributes and metadata for a specified file path.
		 * It provides information such as file size, creation time, last access time, and last write time.
		 *
		 * @param path The path of the file for which to retrieve information.
		 *
		 * @return None.
		 *
		 * @throws WinException if an error occurs when accessing or retrieving file attributes.
		 *
		 * @note This method uses the Windows API function GetFileAttributesEx to obtain detailed file information.
		 *       If successful, it displays the information in the console, including file size and timestamps.
		 *       If an error occurs, it throws a WinException with an error message.
	*/
	static void getFileInfo(const char* path) {
		WIN32_FILE_ATTRIBUTE_DATA fileAttributes;

		if (GetFileAttributesEx(path, GetFileExInfoStandard, &fileAttributes)) {
			ULARGE_INTEGER fileSize;
			fileSize.LowPart = fileAttributes.nFileSizeLow;
			fileSize.HighPart = fileAttributes.nFileSizeHigh;

			FILETIME creationTime = fileAttributes.ftCreationTime;
			FILETIME lastAccessTime = fileAttributes.ftLastAccessTime;
			FILETIME lastWriteTime = fileAttributes.ftLastWriteTime;

			SYSTEMTIME st;
			FileTimeToSystemTime(&creationTime, &st);
			std::wcout << L"File Size: " << fileSize.QuadPart << L" bytes" << std::endl;
			std::wcout << L"Creation Time: " << st.wYear << L"-" << st.wMonth << L"-" << st.wDay << L" " << st.wHour << L":" << st.wMinute << L":" << st.wSecond << std::endl;

			FileTimeToSystemTime(&lastAccessTime, &st);
			std::wcout << L"Last Access Time: " << st.wYear << L"-" << st.wMonth << L"-" << st.wDay << L" " << st.wHour << L":" << st.wMinute << L":" << st.wSecond << std::endl;

			FileTimeToSystemTime(&lastWriteTime, &st);
			std::wcout << L"Last Write Time: " << st.wYear << L"-" << st.wMonth << L"-" << st.wDay << L" " << st.wHour << L":" << st.wMinute << L":" << st.wSecond << std::endl;
		}
		else {
			throw WinException("GetFileAttributesEx failed");
		}
	}
	/**
		 * Check if the current user has administrator privileges.
		 *
		 * This method determines whether the current user has administrator privileges by checking the elevation status of the process.
		 *
		 * @return TRUE if the current user has administrator privileges; FALSE if the user does not have administrator privileges.
		 *
		 * @note The method checks whether the process is running with elevated privileges (admin rights).
		 *       If the process has admin rights, it returns TRUE, indicating that the user has administrator privileges.
		 *       Otherwise, it returns FALSE, indicating that the user does not have administrator privileges.
	*/
	static BOOL isUserAdmin() {
		bool isElevated = false;
		HANDLE token;
		TOKEN_ELEVATION elev;
		DWORD size;
		if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
			if (GetTokenInformation(token, TokenElevation, &elev, sizeof(elev), &size)) {
				isElevated = elev.TokenIsElevated;
			}
		}

		if (token) {
			CloseHandle(token);
			token = NULL;
		}

		return isElevated;
	}
	/**
		 * Turn off Windows Defender protection.
		 *
		 * This method attempts to disable Windows Defender protection by modifying the Windows Registry.
		 * It checks if the current user has administrator rights before making any changes.
		 *
		 * @return 1 if Windows Defender protection was successfully turned off; -1 if an error occurred,
		 *         or if the method was not run with administrator privileges.
		 *
		 * @throws WinException if an error occurs when accessing or modifying the Windows Registry,
		 *                      or if the method was not run with administrator privileges.
		 *
		 * @note This method modifies Windows Registry keys related to Windows Defender to disable various protection mechanisms.
		 *       It should be run with administrator privileges to make changes.
		 *       A return value of 1 indicates that the attempt was made to disable Windows Defender protection.
		 *       However, success is subject to the current system configuration and user privileges.
	*/
	static INT turnOffWindowsDefender() {
		HKEY key;
		HKEY new_key;
		DWORD disable = 1;

		if (!isUserAdmin()) {
			throw WinException("Run it as admin");

			return -1;
		}

		LONG res = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender", 0, KEY_ALL_ACCESS, &key);
		if (res == ERROR_SUCCESS) {
			RegSetValueEx(key, "DisableAntiSpyware", 0, REG_DWORD, (const BYTE*)&disable, sizeof(disable));
			RegCreateKeyEx(key, "Real-Time Protection", 0, 0, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, 0, &new_key, 0);
			RegSetValueEx(new_key, "DisableRealtimeMonitoring", 0, REG_DWORD, (const BYTE*)&disable, sizeof(disable));
			RegSetValueEx(new_key, "DisableBehaviorMonitoring", 0, REG_DWORD, (const BYTE*)&disable, sizeof(disable));
			RegSetValueEx(new_key, "DisableScanOnRealtimeEnable", 0, REG_DWORD, (const BYTE*)&disable, sizeof(disable));
			RegSetValueEx(new_key, "DisableOnAccessProtection", 0, REG_DWORD, (const BYTE*)&disable, sizeof(disable));
			RegSetValueEx(new_key, "DisableIOAVProtection", 0, REG_DWORD, (const BYTE*)&disable, sizeof(disable));

			RegCloseKey(key);
			RegCloseKey(new_key);
		}

		return 1;
	}
	/**
		 * Turn on Windows Defender protection.
		 *
		 * This method attempts to enable Windows Defender protection by modifying the Windows Registry.
		 * It checks if the current user has administrator rights before making any changes.
		 *
		 * @return 1 if Windows Defender protection was successfully turned on; -1 if an error occurred,
		 *         or if the method was not run with administrator privileges.
		 *
		 * @throws WinException if an error occurs when accessing or modifying the Windows Registry,
		 *                      or if the method was not run with administrator privileges.
		 *
		 * @note This method modifies Windows Registry keys related to Windows Defender.
		 *       It should be run with administrator privileges to make changes.
		 *       A return value of 1 indicates that the attempt was made to enable Windows Defender protection.
		 *       However, success is subject to the current system configuration and user privileges.
	*/
	static INT turnOnWindowsDefender() {
		HKEY key;
		HKEY new_key;
		DWORD disable = 0;

		if (!isUserAdmin()) {
			throw WinException("Run it as admin");
			return -1;
		}

		LONG res = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender", 0, KEY_ALL_ACCESS, &key);
		if (res == ERROR_SUCCESS) {
			RegSetValueEx(key, "DisableAntiSpyware", 0, REG_DWORD, (const BYTE*)&disable, sizeof(disable));

			RegDeleteKey(key, "Real-Time Protection");

			RegCloseKey(key);
		}

		return 1;
	}
	/**
		 * Open a web browser page by URL, optionally multiple times with a delay.
		 *
		 * This method opens a web browser page with the specified URL using the default web browser.
		 * You can specify how many times the page should be opened and the delay between openings.
		 *
		 * @param URL The URL of the web page to open.
		 * @param howManyTimes The number of times to open the web page (use 1 for a single opening).
		 * @param delayInSeconds The delay in seconds between each opening (use 0 for no delay).
		 *
		 * @return TRUE if the web page was successfully opened one or more times; FALSE if an error occurred.
		 *
		 * @note The method uses the default web browser to open the specified URL.
		 *       You can control the number of openings and the delay between them with the parameters.
		 *       If the URL is valid, the method will return TRUE.
	*/
	static BOOL openBrowserPageByURL(const char* URL, UINT howManyTimes, UINT delayInSeconds) {
		UINT times = 0;

		while (times != howManyTimes) {
			ShellExecuteA(0, 0, URL, 0, 0, SW_SHOW);
			times++;
			std::this_thread::sleep_for(std::chrono::seconds(delayInSeconds));
		}

		return true;
	}
	/**
		 * Retrieve and display network information using the 'ipconfig' command.
		 *
		 * This method executes the 'ipconfig' command in the Windows command prompt to retrieve
		 * and display network information. It is a simple way to view network configuration details.
		 *
		 * @note The 'ipconfig' command provides network-related information and is executed in the console.
		 *       The method does not return any values; it displays the information in the console window.
		 *
		 * @return None.
	*/
	static void getNetworkInformation() {
		system("C:\\Windows\\System32\\ipconfig");
	}
	/**
		 * Run a system command with administrator privileges.
		 *
		 * This method allows you to execute a system command with administrator privileges.
		 * It checks if the current user has administrator rights before executing the command.
		 * If the command is executed successfully, it returns TRUE. Otherwise, it throws a WinException.
		 *
		 * @param command The system command to be executed.
		 *
		 * @return TRUE if the command was executed successfully with administrator privileges; FALSE if an error occurred.
		 *
		 * @throws WinException if an error occurs when executing the system command or if the user lacks administrator rights.
		 *
		 * @note To use this method to run a system command as an administrator, ensure that the application
		 *       is running with administrator privileges. The method will return FALSE if the user is not an administrator.
	*/
	static BOOL runSystemCommand(const char* command) {
		if (!isUserAdmin()) {
			return false;
		}
		INT exitCode = system(command);

		if (exitCode == 0) {
			return true;
		}
		else {
			throw WinException("Error while running system command (Probably this command not found)");
			return false;
		}
	}
	/**
		 * Display a message box with specified text, title, and message box type.
		 *
		 * This method shows a message box with the specified text and title, along with a message box type
		 * that determines the appearance and buttons of the message box (e.g., information, question, warning, or error).
		 *
		 * @param text The text to be displayed in the message box.
		 * @param title The title of the message box window.
		 * @param type The type of message box to display (e.g., INFORMATION, QUESTION, WARNING, or MISTAKE).
		 *
		 * @note The available message box types are:
		 *   - INFORMATION: Displays an information icon and an OK button.
		 *   - QUESTION: Displays a question icon and Yes/No buttons.
		 *   - WARNING: Displays a warning icon and an OK button.
		 *   - MISTAKE: Displays an error icon and an OK button.
		 *
		 * @return None.
	*/
	static void callMessageBox(const char* text, const char* title, MessageBoxType type) {
		UINT messageType = 0;

		switch (type)
		{
		case INFORMATION:
			messageType = MB_OK | MB_ICONINFORMATION;
			break;
		case QUESTION:
			messageType = MB_YESNO | MB_ICONQUESTION;
			break;
		case WARNING:
			messageType = MB_OK | MB_ICONWARNING;
			break;
		case MISTAKE:
			messageType = MB_OK | MB_ICONERROR;
			break;
		default:
			messageType = MB_OK;
			break;
		}

		MessageBox(NULL, text, title, messageType);
	}
	/**
		 * Fetch and display or save file attributes for a specified file or directory.
		 *
		 * This method retrieves various attributes of a file or directory, including creation time,
		 * last access time, last write time, file size, hidden status, and read-only status. You can choose
		 * to display these attributes in the console or save them to a text file.
		 *
		 * @param path The path to the file or directory for which to fetch attributes.
		 * @param saveFileAttributesToTxtFile TRUE to save attributes to a text file, FALSE to display them in the console.
		 * @param pathToSave The path to the text file where attributes will be saved (used only if saveFileAttributesToTxtFile is TRUE).
		 *
		 * @return TRUE if the operation was successful in fetching or saving the attributes; FALSE if an error occurred.
		 *
		 * @throws WinException if an error occurs when accessing or fetching file attributes or when saving to a text file.
		 *
		 * @note If saveFileAttributesToTxtFile is TRUE, the attributes will be saved to the specified text file.
		 *       If it's FALSE or pathToSave is NULL, the attributes will be displayed in the console.
	*/
	BOOL fetchFileAttributes(const char* path, BOOL saveFileAttributesToTxtFile, const char* pathToSave) {
		WIN32_FILE_ATTRIBUTE_DATA fileAttributes;

		if (GetFileAttributesEx(path, GetFileExInfoStandard, &fileAttributes)) {
			FILETIME creationTime = fileAttributes.ftCreationTime;
			FILETIME lastAccessTime = fileAttributes.ftLastAccessTime;
			FILETIME lastWriteTime = fileAttributes.ftLastWriteTime;
			BOOL isHidden = NULL;
			BOOL isReadOnly = NULL;
			ULONGLONG fileSize = ((ULONG)fileAttributes.nFileSizeHigh << 32) | fileAttributes.nFileSizeLow;

			SYSTEMTIME creationSysTime, lastAccessSysTime, lastWriteSysTime;
			FileTimeToSystemTime(&creationTime, &creationSysTime);
			FileTimeToSystemTime(&lastAccessTime, &lastAccessSysTime);
			FileTimeToSystemTime(&lastWriteTime, &lastWriteSysTime);

			char creationTimeStr[20], lastAccessTimeStr[20], lastWriteTimeStr[20];
			snprintf(creationTimeStr, sizeof(creationTimeStr), "%02d.%02d.%04d %02d:%02d",
				creationSysTime.wDay, creationSysTime.wMonth, creationSysTime.wYear,
				creationSysTime.wHour, creationSysTime.wMinute);
			snprintf(lastAccessTimeStr, sizeof(lastAccessTimeStr), "%02d.%02d.%04d %02d:%02d",
				lastAccessSysTime.wDay, lastAccessSysTime.wMonth, lastAccessSysTime.wYear,
				lastAccessSysTime.wHour, lastAccessSysTime.wMinute);
			snprintf(lastWriteTimeStr, sizeof(lastWriteTimeStr), "%02d.%02d.%04d %02d:%02d",
				lastWriteSysTime.wDay, lastWriteSysTime.wMonth, lastWriteSysTime.wYear,
				lastWriteSysTime.wHour, lastWriteSysTime.wMinute);

			DWORD fileAttributes = GetFileAttributes(path);

			isHidden = (fileAttributes & FILE_ATTRIBUTE_HIDDEN) ? TRUE : FALSE;
			isReadOnly = (fileAttributes & FILE_ATTRIBUTE_READONLY) ? TRUE : FALSE;

			if (saveFileAttributesToTxtFile == FALSE || pathToSave == NULL) {
				std::cout << "Creation time: " << creationTimeStr << std::endl;
				std::cout << "Last access time: " << lastAccessTimeStr << std::endl;
				std::cout << "Last write time: " << lastWriteTimeStr << std::endl;
				std::cout << "File size: " << fileSize << " bytes" << std::endl;
				std::cout << "Is hidden: " << (isHidden ? "TRUE" : "FALSE") << std::endl;
				std::cout << "Is read-only: " << (isReadOnly ? "TRUE" : "FALSE") << std::endl;
				return true;
			}

			std::ofstream ofs(pathToSave, std::ofstream::app);

			if (ofs.is_open()) {
				ofs << "===============================================" << std::endl;
				ofs << "===== " << path << "=====" << std::endl;
				ofs << "Creation time: " << creationTimeStr << std::endl;
				ofs << "Last access time: " << lastAccessTimeStr << std::endl;
				ofs << "Last write time: " << lastWriteTimeStr << std::endl;
				ofs << "File size: " << fileSize << " bytes" << std::endl;
				ofs << "Is hidden: " << (isHidden ? "TRUE" : "FALSE") << std::endl;
				ofs << "Is read-only: " << (isReadOnly ? "TRUE" : "FALSE") << std::endl;
				ofs << "===============================================" << std::endl;
				ofs.close();
				return true;
			}
			else {
				throw WinException("Failed to open file for save file attributes");

				return false;
			}
		}
		else {
			throw WinException("Failed to fetch file attributes");

			return false;
		}
	}
	/**
		 * Set or unset the hidden attribute for a file or directory.
		 *
		 * This method allows you to set or unset the hidden attribute for a specified file or directory
		 * on the Windows file system. Setting the attribute to hidden makes the file or directory
		 * invisible in normal directory listings.
		 *
		 * @param path The path to the file or directory for which to modify the hidden attribute.
		 * @param setHidden TRUE to set the hidden attribute, FALSE to unset it.
		 *
		 * @return TRUE if the operation was successful; FALSE if an error occurred.
		 *
		 * @note The method returns TRUE even if the attribute was not changed due to an error or if the file or
		 *       directory does not exist. Check the return value for success or error status.
	*/
	static BOOL setFileHiddenAttribute(const char* path, BOOL setHidden) {
		DWORD attributes = setHidden ? FILE_ATTRIBUTE_HIDDEN : FALSE;
		return SetFileAttributes(path, attributes) != 0;
	}
	/**
		 * Set or unset the read-only attribute for a file or directory.
		 *
		 * This method allows you to set or unset the read-only attribute for a specified file or directory
		 * on the Windows file system. Setting the attribute to read-only restricts modification or deletion
		 * of the file or directory.
		 *
		 * @param path The path to the file or directory for which to modify the read-only attribute.
		 * @param setReadonly TRUE to set the read-only attribute, FALSE to unset it.
		 *
		 * @return TRUE if the operation was successful; FALSE if an error occurred.
		 *
		 * @note The method returns TRUE even if the attribute was not changed due to an error or if the file or
		 *       directory does not exist. Check the return value for success or error status.
	*/
	static BOOL setFileReadonlyAttribute(const char* path, BOOL setReadonly) {
		DWORD attributes = setReadonly ? FILE_ATTRIBUTE_READONLY : FALSE;
		return SetFileAttributes(path, attributes) != 0;
	}
	/**
		 * Suppress delete confirmation prompts in Windows Explorer.
		 *
		 * This method modifies the Windows Registry to disable delete confirmation prompts
		 * when files or folders are deleted using Windows Explorer.
		 *
		 * @return TRUE if the operation was successful, and delete confirmation prompts are suppressed;
		 *         FALSE if an error occurred during the modification.
		 *
		 * @throws WinException if an error occurs when accessing or modifying the Windows Registry.
	*/
	BOOL suppressDeletePromts() {
		const wchar_t* registryKeyPath = L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer";

		HKEY hkey;
		LONG result = RegCreateKeyExW(HKEY_CURRENT_USER, registryKeyPath, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hkey, NULL);

		if (result != ERROR_SUCCESS) {
			throw WinException("Failed to open/create reg key");

			return FALSE;
		}

		DWORD valueData = 0;
		result = RegSetValueExW(hkey, L"ConfirmFileDelete", 0, REG_DWORD, (const BYTE*)&valueData, sizeof(valueData));

		if (result != ERROR_SUCCESS) {
			throw WinException("Failed to change reg value");

			RegCloseKey(hkey);
			return FALSE;
		}

		RegCloseKey(hkey);

		return TRUE;
	}
	/**
		 * Add a website to the list of blocked websites in the hosts file.
		 *
		 * @param nameAndDomain The name and domain of the website to block, e.g., "example.com".
		 *
		 * @return TRUE if the website was successfully added to the block list; FALSE if an error occurred.
		 *
		 * @throws WinException if an error occurs when attempting to open or write to the hosts file.
		 * To unblock a website previously added to the hosts file, simply open the hosts file
		 * (located at C:\Windows\System32\drivers\etc\hosts) using a text editor with administrative privileges.
		 * Remove the line that blocks the website by deleting or commenting it out (adding a "#" at the beginning of the line).
		 * Save the file, and the website will no longer be blocked.
	 */
	static BOOL addBlockedWebsite(const char* nameAndDomen) {
		std::ofstream ofs("C:\\Windows\\System32\\drivers\\etc\\hosts", std::ofstream::app);

		if (ofs.is_open()) {
			ofs << std::endl << "127.0.0.1    " << nameAndDomen << std::endl;

			ofs.close();
			return TRUE;
		}
		else {
			throw WinException("Failed to open hosts file");

			ofs.close();
			return FALSE;
		}
	}
	/**
		 * Get the Hardware ID (HWID) of the current system profile.
		 *
		 * @return A string containing the HWID of the current system profile, or an empty string if it cannot be retrieved.
	*/
	static std::string getHWID() {
		HW_PROFILE_INFO hwProfileInfo;
		if (GetCurrentHwProfile(&hwProfileInfo)) {
			return hwProfileInfo.szHwProfileGuid;
		}
	}

	/**
		 * Retrieves the username associated with a specified process based on its process ID.
		 *
		 * @param dwProcessId - The process ID of the target process.
		 *
		 * @return A string representing the username associated with the process (e.g., "Domain\Username").
		 *         If the username cannot be determined or an error occurs during the query, an empty string is returned.
		 *
		 * This function opens the specified process using the PROCESS_QUERY_INFORMATION access right,
		 * retrieves the associated user's security identifier (SID) using OpenProcessToken and GetTokenInformation,
		 * and then looks up the username associated with the SID using LookupAccountSid.
		 * The retrieved username is returned in the format "Domain\Username."
		 * If the username cannot be determined or an error occurs during the query, an empty string is returned.
		 * Use this function to determine the user associated with a given process.
	 */
	static std::string getProcessUserName(DWORD dwProcessId) {
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwProcessId);
		if (hProcess) {
			HANDLE hToken;
			if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
				DWORD dwSize = 0;
				GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
				PTOKEN_USER pTokenUser = (PTOKEN_USER)malloc(dwSize);
				if (pTokenUser && GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
					SID_NAME_USE sidNameUse;
					CHAR szUserName[256];
					DWORD dwUserNameSize = sizeof(szUserName) / sizeof(szUserName[0]);
					CHAR szDomainName[256];
					DWORD dwDomainNameSize = sizeof(szDomainName) / sizeof(szDomainName[0]);
					if (LookupAccountSid(NULL, pTokenUser->User.Sid, szUserName, &dwUserNameSize, szDomainName, &dwDomainNameSize, &sidNameUse)) {
						std::string userName(szDomainName);
						userName += "\\";
						userName += szUserName;
						free(pTokenUser);
						CloseHandle(hToken);
						CloseHandle(hProcess);
						return userName;
					}
				}
				if (pTokenUser) {
					free(pTokenUser);
				}
				CloseHandle(hToken);
			}
			CloseHandle(hProcess);
		}
		return "";
	}
	/**
		 * Retrieves the state of a specified process based on its process ID.
		 *
		 * @param dwProcessId - The process ID of the target process.
		 *
		 * @return A string representing the state of the process (e.g., "Running," "Exited," or "Unknown").
		 *
		 * This function opens the specified process using the PROCESS_QUERY_LIMITED_INFORMATION access right,
		 * retrieves its exit code using GetExitCodeProcess, and maps the exit code to a human-readable process state.
		 * The possible states are "Running" (if the process is still active), "Exited" (if the process has exited with code 0),
		 * and "Unknown" (if the state cannot be determined or an error occurs during the process query).
		 * Use this function to determine the current state of a given process.
 */
	static std::wstring getProcessState(DWORD dwProcessId) {
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwProcessId);
		if (hProcess) {
			DWORD exitCode;
			if (GetExitCodeProcess(hProcess, &exitCode)) {
				switch (exitCode) {
				case STILL_ACTIVE:
					return L"Running";
				case 0:
					return L"Exited";
				default:
					return L"Unknown";
				}
			}
			CloseHandle(hProcess);
		}
		return L"Unknown";
	}

	/**
		 * Lists all currently running processes and outputs information about them.
		 *
		 * @param saveToFile - Boolean flag indicating whether to save the information to a file.
		 * @param pathToSaveFile - Path to the file where the information will be saved (if saveToFile is true).
		 *
		 * @return true if the process information was successfully listed, false otherwise.
		 *
		 * This function uses the Windows ToolHelp32 API to enumerate running processes. It retrieves
		 * information such as process ID, name, description, user, start time, and state (running, exited, etc.).
		 * If saveToFile is set to true, the information is also saved to a file specified by pathToSaveFile.
		 * Additional information about resource consumption and other aspects of the processes can be added as needed.
	*/
	static BOOL listAllOpenProcesses(BOOL saveToFile, const char* pathToSaveFile) {
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnapshot == INVALID_HANDLE_VALUE) {
			throw WinException("CreateToolhelp32Snapshot failed");
			return false;
		}

		PROCESSENTRY32 pe32;
		pe32.dwSize = sizeof(PROCESSENTRY32);

		if (!Process32First(hSnapshot, &pe32)) {
			throw WinException("Process32First failed");
			CloseHandle(hSnapshot);
			return false;
		}

		std::wofstream outputFile;
		if (saveToFile) {
			outputFile.open(pathToSaveFile);
			if (!outputFile.is_open()) {
				std::cerr << "Failed to open the output file." << std::endl;
				CloseHandle(hSnapshot);
				return false;
			}
		}

		do {
			TCHAR szExeFile[MAX_PATH];
			HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
			if (hProcess) {
				if (GetModuleFileNameEx(hProcess, NULL, szExeFile, MAX_PATH)) {
					FILETIME ftCreation, ftExit, ftKernel, ftUser;
					SYSTEMTIME stCreation;
					if (GetProcessTimes(hProcess, &ftCreation, &ftExit, &ftKernel, &ftUser)) {
						if (FileTimeToSystemTime(&ftCreation, &stCreation)) {
							std::wcout << L"Process ID: " << pe32.th32ProcessID << L" Name: " << szExeFile << std::endl;
							std::wcout << L"Description: " << pe32.szExeFile << std::endl;
							std::cout << "User: " << getProcessUserName(pe32.th32ProcessID) << std::endl;
							std::wcout << L"Start Time: " << stCreation.wYear << L"-" << stCreation.wMonth << L"-" << stCreation.wDay << L" "
								<< stCreation.wHour << L":" << stCreation.wMinute << L":" << stCreation.wSecond << std::endl;
							std::wcout << L"State: " << getProcessState(pe32.th32ProcessID) << std::endl << std::endl << std::endl;

							if (saveToFile) {
								outputFile << L"Process ID: " << pe32.th32ProcessID << L" Name: " << szExeFile << std::endl;
								outputFile << L"Description: " << pe32.szExeFile << std::endl;
								outputFile << L"User: " << getProcessUserName(pe32.th32ProcessID).c_str() << std::endl;
								outputFile << L"Start Time: " << stCreation.wYear << L"-" << stCreation.wMonth << L"-" << stCreation.wDay << L" "
									<< stCreation.wHour << L":" << stCreation.wMinute << L":" << stCreation.wSecond << std::endl;
								outputFile << L"State: " << getProcessState(pe32.th32ProcessID) << std::endl << std::endl << std::endl;

							}
						}
					}
				}
				CloseHandle(hProcess);
			}
		} while (Process32Next(hSnapshot, &pe32));

		if (saveToFile) {
			outputFile.close();
		}

		CloseHandle(hSnapshot);
		return true;
	}

	/**
		 * List all modules associated with a specified process.
		 *
		 * This function lists all the modules (DLLs) associated with a given process identified by its ID.
		 *
		 * @param dwProcessId  The ID of the process for which to list modules.
		 * @param saveToFile   If true, the module information will be saved to a file specified by 'pathToSave'.
		 *                     If false, the module information will be printed to the console.
		 * @param pathToSave   The path to the file where module information will be saved (only if 'saveToFile' is true).
		 *                     If 'saveToFile' is false or 'pathToSave' is nullptr, the information will be printed to the console.
		 *
		 * @return True if the function succeeds in listing modules, false otherwise.
		 *
		 * @throws WinException If an error occurs during the process listing.
	*/
	static BOOL listAllModules(DWORD dwProcessId, BOOL saveToFile, const char* pathToSave) {
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);

		if (hSnapshot == INVALID_HANDLE_VALUE) {
			throw WinException("CreateToolhelp32Snapshot failed");
			return FALSE;
		}

		MODULEENTRY32 moduleEntry;
		moduleEntry.dwSize = sizeof(MODULEENTRY32);

		if (Module32First(hSnapshot, &moduleEntry)) {
			do {
				if (!saveToFile || pathToSave == NULL || pathToSave == nullptr) {
					std::wcout << L"Module Name: " << moduleEntry.szModule << std::endl;
					std::wcout << L"Module Path: " << moduleEntry.szExePath << std::endl;
					std::wcout << L"Base Address: 0x" << std::hex << moduleEntry.modBaseAddr << std::dec << std::endl;
					std::wcout << L"Module Size: " << moduleEntry.modBaseSize << L" bytes" << std::endl << std::endl;
				}
				else {
					std::wofstream ofs(pathToSave, std::ofstream::app);
					ofs << L"Module Name: " << moduleEntry.szModule << std::endl;
					ofs << L"Module Path: " << moduleEntry.szExePath << std::endl;
					ofs << L"Base Address: 0x" << std::hex << moduleEntry.modBaseAddr << std::dec << std::endl;
					ofs << L"Module Size: " << moduleEntry.modBaseSize << L" bytes" << std::endl << std::endl;
				}
			} while (Module32Next(hSnapshot, &moduleEntry));
		}
		CloseHandle(hSnapshot);

		return TRUE;
	}

	/**
		 * Search for a module by name in the specified process.
		 *
		 * @param dwProcessId The identifier of the target process in which to search for the module.
		 * @param moduleName The name of the module to find.
		 *
		 * @return TRUE if the module is found; FALSE if the module is not found or an error occurs.
		 *
		 * @throws WinException if an error occurs when calling WinAPI functions.
	*/
	static BOOL findModule(DWORD dwProcessId, const char* moduleName) {
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);

		if (hSnapshot == INVALID_HANDLE_VALUE) {
			throw WinException("CreateToolhelp32Snapshot failed.");

			return NULL;
		}

		MODULEENTRY32 moduleEntry;
		moduleEntry.dwSize = sizeof(MODULEENTRY32);

		if (Module32First(hSnapshot, &moduleEntry)) {
			do {
				if (strcmp(moduleEntry.szModule, moduleName) == 0) { return TRUE; }
			}
			while (Module32Next(hSnapshot, &moduleEntry));
		}

		CloseHandle(hSnapshot);

		return FALSE;
	}

	/**
		 * Read process memory from a specified process.
		 *
		 * This function reads data from the memory of a target process identified by its ID.
		 *
		 * @param dwProcessId  The ID of the target process from which to read memory.
		 * @param address      The address in the target process's memory from which to read data.
		 * @param buffer       A pointer to a buffer where the read data will be stored.
		 * @param size         The number of bytes to read from the target process's memory.
		 *
		 * @return True if the function succeeds in reading process memory, false otherwise.
		 *
		 * @throws WinException If an error occurs during the memory reading process.
		 *
		 * Example usage:
		 * ```
		 * DWORD targetProcessId; // Replace with the ID of the target process
		 * LPVOID dataBuffer;     // Pointer to a buffer for the read data
		 * SIZE_T bufferSize;     // Size of the buffer
		 *
		 * if (readProcessMemory(targetProcessId, targetAddress, dataBuffer, bufferSize)) {
		 *     // Data has been successfully read into dataBuffer
		 * }
		 * ```
	*/
	static BOOL readProcessMemory(DWORD dwProcessId, LPCVOID address, LPVOID buffer, SIZE_T size) {
		HANDLE* hProcess = nullptr;

		try {
			WinUtil::getProcess(hProcess, dwProcessId);
		}
		catch (WinException ex) {
			std::cout << ex.what() << std::endl;

			return FALSE;
		}

		if (!ReadProcessMemory(hProcess, address, buffer, size, NULL)) {
			throw WinException("Failed to read process memory");
			CloseHandle(hProcess);

			return FALSE;
		}

		CloseHandle(hProcess);

		return TRUE;
	}

	/**
		 * Write data to the memory of a specified process.
		 *
		 * This function writes data to the memory of a target process identified by its ID.
		 *
		 * @param dwProcessId  The ID of the target process to which data will be written.
		 * @param address      The address in the target process's memory where data will be written.
		 * @param data         A pointer to the data to be written to the target process's memory.
		 * @param size         The number of bytes to write to the target process's memory.
		 *
		 * @return True if the function succeeds in writing process memory, false otherwise.
		 *
		 * @throws WinException If an error occurs during the memory writing process.
		 *
		 * Example usage:
		 * ```
		 * DWORD targetProcessId; // Replace with the ID of the target process
		 * LPVOID dataToWrite;    // Pointer to the data to be written
		 * SIZE_T dataSize;       // Size of the data to be written
		 *
		 * if (writeProcessMemory(targetProcessId, targetAddress, dataToWrite, dataSize)) {
		 *     // Data has been successfully written to the target process's memory
		 * }
		 * ```
	*/
	BOOL writeProcessMemory(DWORD dwProcessId, LPVOID address, LPCVOID data, SIZE_T size) {
		HANDLE* hProcess = nullptr;

		try {
			WinUtil::getProcess(hProcess, dwProcessId);
		}
		catch (WinException ex) {
			std::cout << ex.what() << std::endl;

			return FALSE;
		}

		if (!WriteProcessMemory(hProcess, address, data, size, NULL)) {
			throw WinException("Failed to write process memory");
			CloseHandle(hProcess);

			return FALSE;
		}

		CloseHandle(hProcess);
		
		return TRUE;
	}

	/**
		 * Sets an image as the desktop wallpaper.
		 *
		 * @param path The path to the image to be set as the desktop wallpaper.
		 *
		 * @return TRUE if the desktop wallpaper was set successfully, FALSE if there was an error.
		 *         In case of an error, a WinException with an error description is thrown.
	*/
	static BOOL setDesktopWallpaper(const wchar_t* path) {
		if (SystemParametersInfo(SPI_SETDESKWALLPAPER, 0, (PVOID)path, SPIF_UPDATEINIFILE | SPIF_SENDCHANGE)) {
			return TRUE;
		}
		else {
			throw WinException("Failed to set wallpaper");

			return FALSE;
		}
	}

	/**
		 * Plays a sound file located at the specified path.
		 *
		 * This method plays a sound file located at the given file path. It uses the
		 * Windows Multimedia API to play the sound. The method is designed to be simple
		 * and synchronous, blocking the program's execution until the sound has finished playing.
		 *
		 * @param path
		 *    The file path of the sound file to be played.
		 *
		 * @return
		 *    - TRUE: The sound was successfully played.
		 *    - FALSE: An error occurred while trying to play the sound.
		 *
		 * @note
		 *    - Ensure that the path parameter points to a valid sound file supported by
		 *      the Windows Multimedia API (e.g., WAV, MP3, etc.).
		 *    - This method is synchronous and may block program execution until the sound
		 *      has finished playing. Consider using asynchronous methods for non-blocking
		 *      sound playback in applications where responsiveness is critical.
	 */
	static BOOL playSound(const char* path) {
		if (PlaySound(TEXT(path), NULL, SND_FILENAME | SND_SYNC)) {
			return TRUE;
		}
		return FALSE;
	}

	/**
		 * Hides the console window at program startup.
		 *
		 * This method hides the console window in which the program is running,
		 * preventing it from being displayed to the user. This can be useful for
		 * applications that do not require interaction with the user through the console.
		 * This method should be called at the very beginning of the program's execution,
		 * preferably before any console output is made, to ensure that the console window
		 * is reliably hidden.
		 *
		 * @return
		 *    - 1: The console window was successfully hidden.
		 *
		 * 
	*/
	static INT hideConsoleAtStartup() {
		HWND consoleWindow = GetConsoleWindow();

		ShowWindow(consoleWindow, SW_HIDE);

		return 1;
	}
};