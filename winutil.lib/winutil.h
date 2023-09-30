// Make sure that multibyte encoding support is enabled in your visual studio project properties
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

/*
	This is enum "MessageBoxType" used in method void WinUtil::callMessageBox(const char* text, const char* title, MessageBoxType type)
	It is used for type of Windows Message Box (icon, sound and etc.) Try it out and choose what kind of message box types
	Do u need in your specific situation.
*/

enum MessageBoxType {
	INFORMATION,
	QUESTION,
	WARNING,
	MISTAKE
};
/*
	I decided to make my own unique class for exceptions, they are used everywhere to catch errors in each method.

	Usage example:

	try {
		WinUtil::shutdown(FALSE);
	}
	catch(WinException ex) {
		std::cout << ex.what() << std::endl;
	}

	I advise you to cover any method with such a wrapper
*/
class WinException : public std::runtime_error {
public:
	WinException(const std::string& message) : std::runtime_error(message) {
		errorMsg = message + "\nError code: " + std::to_string(GetLastError());
	}

	const char* what() const noexcept override {
		return errorMsg.c_str();
	}
private:
	std::string errorMsg;
};

class WinUtil {
public:

	/*

		The method the essence of which is to turn off the system or restart it by BOOL rebootAfterShutdown argument.
		Example: shutdown(TRUE) --- It will be restart ur system.

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

	/*

		The method which help to get PID by process name.
		You can view the PID of any process in the task manager yourself, this method will do it only by the process name.
		Example: getProcessId("csgo.exe");   >_<   getProcessId(chrome.exe);

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

	/*

		The method which completes process by him name.
		Example: killProcess("chrome.exe");

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

	/*

		The method which help you to get handle to process.
		Example:
		HANDLE* h;         WinUtil::getProcess(h, 5154);

	*/

	static BOOL getProcess(HANDLE* handleToProcess, DWORD pid) {
		*handleToProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);

		if (*handleToProcess == NULL) {
			throw WinException("Failed to get process with " + std::string(std::to_string(pid)) + " pid");

			return FALSE;
		}
		return TRUE;
	}

	static BOOL closeHandle(HANDLE* handleToProcess) {
		if (*handleToProcess != NULL && !CloseHandle(*handleToProcess)) {
			throw WinException("Failed to close handle");
			return FALSE;
		}

		*handleToProcess = nullptr;

		return TRUE;
	}


	/*

		The method which help u with opening file by path;
		Example: WinUtil::openFile("C:\\1.exe");

	*/

	static BOOL openFile(const char* path) {
		HINSTANCE result = ShellExecute(NULL, "open", path, NULL, NULL, SW_SHOWNORMAL);

		if ((intptr_t)result <= 32) {
			throw WinException("Failed to open file by path");

			return false;
		}

		return true;
	}

	/*

		The method which help u creating directories.
		Example: WinUtil::createDirectory("C:\\folder");

	*/

	static BOOL createDirectory(const char* path) {
		if (CreateDirectory(path, NULL) == FALSE) {
			throw WinException("Failed to create directory");
			return FALSE;
		}

		return TRUE;
	}

	/*

		The method which help u with creating files.
		Example: WinUtil::createFile("C:\\vir.exe");

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

	/*

		The method which help u with moves file (also its apply rename file);
		Example: WinUtil::moveFiles("C:\\1.txt", "C:\\2.txt"); --- It will be move file 1.txt to 2.txt

	*/

	static BOOL moveFiles(const char* path, const char* newPath) {
		if (MoveFile(path, newPath) == FALSE) {
			throw WinException("Failed to move file by path");

			return false;
		}

		return true;
	}

	/*

		The method which help u with deleting files by path.
		Example: WinUtil::deleteFile("C:\\empty.txt");

	*/

	static BOOL deleteFile(const char* path) {
		if (DeleteFile(path) == FALSE) {
			throw WinException("Failed to delete file");

			return false;
		}

		return true;
	}

	/*

		The method which help u with deleting directories by path.
		Example: WinUtil::deleteFile("C:\\someFolder");

	*/

	static BOOL deleteDirectory(const char* path) {
		if (RemoveDirectory(path) == FALSE) {
			throw WinException("Failed to delete directory");

			return false;
		}

		return true;
	}

	/*

		Supportive callback for method WinUtil::gellAllRuntimeWindows();
		Nevermind.

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
	/*

		The method which outputs in console all runtime windows and their PID now.
		Most likely it will be more useful if it saves this information to some file, you can try.

	*/
	static void getAllRuntimeWindows() {
		EnumWindows(EnumWindowsProc, 0);
	}
	/*

		The method which call BSOD. <Do you really need this?>

	*/
	typedef NTSTATUS(NTAPI* pdef_NtRaiseHardError)(NTSTATUS ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask OPTIONAL, PULONG_PTR Parameters, ULONG ResponseOption, PULONG Response);
	typedef NTSTATUS(NTAPI* pdef_RtlAdjustPrivilege)(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);

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
	/*

		The method which get process id, process name, pid (process information) and etc. by process name.
		x2 Most likely it will be more useful if it saves this information to some file, you can try.

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
	/*

		The method which get meta data from file.
		x3 Most likely it will be more useful if it saves this information to some file, you can try.

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
	/*

		The method which help u to will know if your program opened as admin mode.

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
	/*

		The method which help u to turn of windows defender forever.

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
	/*

		The method which help u to turn on windows defender back.

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
	/*

		The method which help u open some page of website how many times do u want and also with delay in seconds.
		Example: WinUtil::openBrowserPageByURL("https://google.com", 1, 1);

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
	/*

		The method which help u get information from ipconfig of system

	*/
	static void getNetworkInformation() {
		system("C:\\Windows\\System32\\ipconfig");
	}
	/*

		The method which allows to work with windows command line.
		Example: WinUtil::runSystemCommand("echo Hello World!");

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
	/*

		The method which allows you to call up message box.
		Example: WinUtil::callMessageBox("Some info", "Title of messageBox", // WARNING or MISTAKE or QUESTION or INFORMATION);
		WinUtil::callMessageBox("My program", "Program", INFORMATION);

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
	/*

		The method which allows you to get file attributes (meta data) you also can save it to some file or outputs to console.

		Example: WinUtil::fetchFileAttributes("C:\\file.exe", TRUE, "D:\\fileInfo.txt");

		If u dont want save if to file just set saveFileAttributesToTxtFile argument to FALSE and set NULL to pathToSave argument.


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
	/*

		The method which allows you to set hidden attribute to file. (Hide file from ordinary vision).\

		Also u can unhide some file. Just set argument setHidden to FALSE;

		Example: WinUtil::setFileHiddenAttribute("C:\\wannaHideIt.txt", TRUE); // It will be hide from ordinary vision

	*/
	static BOOL setFileHiddenAttribute(const char* path, BOOL setHidden) {
		DWORD attributes = setHidden ? FILE_ATTRIBUTE_HIDDEN : FALSE;
		return SetFileAttributes(path, attributes) != 0;
	}
	/*

		The method which allows you to set read-only attribute to file.

		Also u can unread-only some file. Just set argument setReadonly to FALSE;

		Example: WinUtil::setFileHiddenAttribute("C:\\wannaReadOnlyIt.txt", TRUE); // It will be read-only yet

	*/
	static BOOL setFileReadonlyAttribute(const char* path, BOOL setReadonly) {
		DWORD attributes = setReadonly ? FILE_ATTRIBUTE_READONLY : FALSE;
		return SetFileAttributes(path, attributes) != 0;
	}
	/*

		The method which allows you to remove pop-up windows with a warning when deleting a some file.

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
	/*

		The method which allows you to block access to some website from browsers.
		In order for everything to work correctly after the successful execution of the method,
		restart your system and try to go to the URL that you passed to the method argument.

		Example: WinUtil::addBlockedWebsite("vk.com");
!!
!!		WARNING - in order to regain access to certain sites that you have blocked, follow this path:
!!		C:\Windows\System32\drivers\etc\hosts
!!		Next, open the hosts file in the form .txt, then remove the URLs that you blocked,
!!		they will be written in a column there, just erase them and save the file.
!!
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
	/*

		The method which allows you to get unique key of your PC hardware.
		You can use this key if you want to make a binding for your software.

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

	BOOL CtrlHandler(DWORD fdwCtrlType, DWORD pid) {
		if (pid != 0) {
			if (fdwCtrlType == CTRL_CLOSE_EVENT) {
				std::cerr << "Attempted to close the protected process." << std::endl;
				return TRUE; // Предотвращаем закрытие
			}
		}
		return FALSE;
	}
};