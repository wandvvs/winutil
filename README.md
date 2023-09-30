# winutil

winutil.h - independent abstract library to build your applications with prepared methods to work with Windows 10.

## Getting Started

1. [Install the winutil.h.zip from the release](https://github.com/wandvvs/winutil/releases/tag/new).
2. Extract the contents of the zip file to your project directory.
3. In your C/C++ source file, include the winutil.h header file by adding the following line at the top:
```cpp
#include "winutil.h"
```
4. To work with the library, you need to enable multibyte encoding in your project. Project properties -> Configuration properties -> General -> Under the "Character Set" dropdown, select "Use Multi-Byte Character Set".
6. You can now use the methods and functions provided by winutil.h in your code. Refer to the documentation or examples provided with the library to understand how to use each method.

## Features
- Shutdown system
- Restart system
- Play sound
- Hide console at startup
- Get process identifier by process name
- Get all runtime windows now
- Get BSOD
- Get process info
- Get file info
- List all open processes to file
- List all modules in process
- Read process memory
- Write process memory
- Get current process state
- Get process user name
- Completes process by name
- Is the program running as an administrator
- Turn off the windows defender forever
- Turn on the windows defender
- Open browser page by url with delay, specific quantity
- Get network information
- Execute windows powershell`s commands
- Call custom message box
- Fetch file attributes
- Set file hidden attribute
- Remove pop-up warning windows when deleting a file
- Block a visit through the browser of any site by URL
- Get hardware identification
- Open file
- Create directory
- Create file
- Moves file
- Delete file
- Delete directory
- Set desktop wallpaper

## Examples
- Get the full path to the executable file by its name
```cpp
 #include "winutil.h"

int main(int argc, char* argv[]) {
    DWORD chromeProcessId = NULL;
    try {
       chromeProcessId = WinUtil::getProcessId("chrome.exe"); // Find PID (process identifier) by name
    }
    catch (WinException ex) {
        std::cout << ex.what() << std::endl;
    }

    HANDLE chromeHandle = nullptr;

    try {
        WinUtil::getProcess(&chromeHandle, chromeProcessId); // Getting handle together with the early found PID
    }
    catch (WinException ex) {
        std::cout << ex.what() << std::endl;
    }

    if (chromeHandle != nullptr) {
        CHAR buffer[MAX_PATH];
        DWORD size = sizeof(buffer) / sizeof(buffer[0]);

        if (QueryFullProcessImageName(chromeHandle, 0, buffer, &size)) { // Get the full path to the executable file
            std::cout << buffer << std::endl; // Output: C:\Program Files\Google\Chrome\Application\chrome.exe
        }
    }

    return 0;
}
```
- Get the current status of the process and the user who started it
```cpp
#include "winutil.h"

int main(int argc, char* argv[]) {
    DWORD pid = WinUtil::getProcessId("chrome.exe");

    std::wstring state = WinUtil::getProcessState(pid);
    std::string user = WinUtil::getProcessUserName(pid);
    
    std::wcout << state << std::endl; // Output: Running
    std::cout << user << std::endl; // Output: DESKTOP-T17FVRA\admin
}
```
- Get all open processes to some file
```cpp
#include "winutil.h"

int main(int argc, char* argv[]) {
    WinUtil::listAllOpenProcesses(TRUE, "C:\\txt.txt");

    return 0;
}
```
Result:
![Output](https://media.discordapp.net/attachments/1130912178124361779/1157372687824474112/12333.png?ex=65185ecf&is=65170d4f&hm=72b6df613b703c12492edd9c2b695aa96f152414d39d68b10572964f6ae4aa81&=&width=851&height=676)
