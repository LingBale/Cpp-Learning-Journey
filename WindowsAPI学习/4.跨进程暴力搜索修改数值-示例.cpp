#include <windows.h>
#include <iostream>
#include <vector>

BOOL EnableDebugPrivilege(){
    HANDLE hToken;
    if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)){
        std::cerr << "OpenProcessToken错误，错误码：" << GetLastError() << std::endl;
        CloseHandle(hToken);
        return false;
    }
    LUID luid;
    if(!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)){
        std::cerr << "LookupPrivilegeValue错误，错误码：" << GetLastError() << std::endl;
        CloseHandle(hToken);
        return false;
    }
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if(!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)){
        std::cerr << "AdjustTokenPrivileges错误，错误码：" << GetLastError() << std::endl;
        CloseHandle(hToken);
        return false;
    }
    CloseHandle(hToken);
    if(GetLastError() == ERROR_NOT_ALL_ASSIGNED){
        std::cerr << "提权失败，请以管理员的身份运行" << std::endl;
        return false;
    }
    return true;
}

int main(){
    // 提权操作及错误处理
    if(EnableDebugPrivilege()){
        std::cout << "提权成功，可以进行相关进程的操作了！" << std::endl;
    }else{ return -1; }

    // 获取目标进程PID
    DWORD pid{};
    std::cout << "请输入目标进程PID：";
    std::cin >> pid;

    // 打开进程及错误处理
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
    if(!hProcess){
        std::cerr << "打开进程失败，错误码：" << GetLastError() << std::endl;
        return 1;
    }

    // 暴力扫描准备
    int Num = 12345;
    std::vector<uintptr_t> addresses;
    BYTE buffer[4] = {};

    // 暴力扫描，这里为了演示将地址缩小到 0x10000 ~ 0x200000
    for(uintptr_t addr = 0x00010000; addr < 0x00200000; addr += 4){
        SIZE_T bytesRead{};
        if(ReadProcessMemory(hProcess, (LPCVOID)addr, buffer, 4, &bytesRead)){
            if(bytesRead == 4){
                int *p = (int*)buffer;
                if(*p == Num){
                    addresses.push_back(addr);
                    std::cout << "找到目标地址：0x" << std::hex << addr << std::dec << std::endl;
                }
            }
        }
    }

    int newNum = 99999;
    for(uintptr_t addr : addresses){
        WriteProcessMemory(hProcess, (LPVOID)addr, &newNum, 4, NULL);
    }

    std::cout << "搜索完毕，共找到 " << addresses.size() << " 个地址并已修改。" << std::endl;
    CloseHandle(hProcess);
    return 0;
}