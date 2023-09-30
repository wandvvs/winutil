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
- Close handle
- Convert file contents to binary code
- Convert from binary code to regular
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
- Result:
![Output](https://media.discordapp.net/attachments/812000275698679818/1157637707774828635/image.png?ex=651955a1&is=65180421&hm=089f9d3f8253e9dbeb8acc3f1c8de488e2377c339524ce67a35cd929c199851c&=&width=599&height=675)

- Convert file contents to binary code
```cpp
#include "winutil.h"

int main() {
	try {
		WinUtil::convertToBinary("C:\\from.txt", "C:\\to.txt");
	}
	catch (WinException ex) {
		std::cout << ex.what() << std::endl;
	}
}
```
- ```from.txt``` (The source file with which we will translate into binary form)
![from](https://media.discordapp.net/attachments/812000275698679818/1157635731834028032/image.png?ex=651953ca&is=6518024a&hm=d23708ca1ce2d3ad18cae1455194ebaecf5392e4a74691f8052ef4d60f8884a9&=)
- ```to.txt``` (The result of converting into binary code)
![to](https://media.discordapp.net/attachments/812000275698679818/1157636109333962823/image.png?ex=65195424&is=651802a4&hm=e98f22828ca8656368ba453fd7aa01198e68bd3aa73425de7e8aef987faf6f87&=&width=1451&height=364)

```010010000110010101101100011011000110111100100000011101110110111101110010011011000110010000100001```
You can try to translate it back through the online service translate from binary to text, there will be "Hello world!"
