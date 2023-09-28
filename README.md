# winutil

winutil.h - independent abstract library to build your applications with prepared methods to work with Windows 10.

## How to use it

1. [Install the winutil.h.zip from the release](https://github.com/wandvvs/winutil/releases/tag/new).
2. Extract the contents of the zip file to your project directory.
3. In your C/C++ source file, include the winutil.h header file by adding the following line at the top:
```cpp
#include "winutil.h"
```
4. To work with the library, you need to enable multibyte encoding in your project. Project properties -> Configuration properties -> General -> Under the "Character Set" dropdown, select "Use Multi-Byte Character Set".
6. You can now use the methods and functions provided by winutil.h in your code. Refer to the documentation or examples provided with the library to understand how to use each method.

## Methodology

1. ```cpp
   static BOOL shutdown(BOOL rebootAfterShutdown);
   ```
   Allows you to turn off or depending on the argument restart the system.
   
2. ```cpp
   static DWORD getProcessId(const char* processName);
   ```
   Finds the PID (Process IDentifier) by the process name.

3. ```cpp
   static INT killProcess(const char* processName)
   ```
   Completes the process by its name.

4. ```cpp
   static INT getProcess(HANDLE* handleToProcess, DWORD pid)
   ```
   Getting handle of process by PID.

5. ```cpp
   static INT getProcess(HANDLE* handleToProcess, DWORD pid)
   ```
   Getting handle of process by PID.

6. ```cpp
   static BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam)
   static void getAllRuntimeWindows()
   ```
   Output in console all runtime windows now.

7. ```cpp
   static BOOL getBSOD()
   ```
   It`s will cause default BSOD.
