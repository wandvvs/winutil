#include "winutil.h"

int main(int argc, char* argv[]) {
    DWORD pid = WinUtil::getProcessId("chrome.exe");

    std::wstring state = WinUtil::getProcessState(pid);
    std::string user = WinUtil::getProcessUserName(pid);
    
    std::wcout << state << std::endl;
    std::cout << user << std::endl;
}