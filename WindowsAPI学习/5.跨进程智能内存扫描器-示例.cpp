#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <iomanip>
#include <string>

// 提权函数
bool EnableDebugPrivilege(){
    HANDLE hToken{};
    if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)){
        std::cerr << "OpenProcessToken错误，错误码：" << GetLastError() << std::endl;
        return false;
    }
    LUID luid{};
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
    if(GetLastError() == ERROR_NOT_ALL_ASSIGNED){
        std::cerr << "权限提升失败，请以管理员的身份运行！" << std::endl;
        CloseHandle(hToken);
        return false;
    }
    CloseHandle(hToken);
    return true;
}
// 通过进程名获取PID
DWORD GetPidByName(const std::string& targetName){
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(hSnap == INVALID_HANDLE_VALUE){ return 1; }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if(Process32First(hSnap, &pe)){
        do{
            if(targetName == pe.szExeFile){
                CloseHandle(hSnap);
                return pe.th32ProcessID;
            }
        }while(Process32Next(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return 0;
}
// 打印进程内存地图
void PrintMemoryMap(HANDLE hProcess) {
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);

    uintptr_t current = (uintptr_t)sysinfo.lpMinimumApplicationAddress;
    uintptr_t end = (uintptr_t)sysinfo.lpMaximumApplicationAddress;

    std::cout << std::hex << std::setfill('0');
    std::cout << "[*]用户空间地址范围：0x" << current << "~0x" << end << std::endl;
    std::cout << "[*]内存页大小：" << sysinfo.dwPageSize << "字节" << std::endl;
    std::cout << "=====================================================================" << std::endl;

    int blockCount = 0;
    while (current < end) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQueryEx(hProcess, (LPVOID)current, &mbi, sizeof(mbi))) {
            current += sysinfo.dwPageSize;
            continue;
        }

        if (mbi.State == MEM_COMMIT && mbi.Protect != PAGE_NOACCESS) {
            blockCount++;

            std::string protectStr;
            if (mbi.Protect & PAGE_EXECUTE_READWRITE) protectStr = "RWX";
            else if (mbi.Protect & PAGE_EXECUTE_READ) protectStr = "RX";
            else if (mbi.Protect & PAGE_READWRITE) protectStr = "RW";
            else if (mbi.Protect & PAGE_READONLY) protectStr = "RO";
            else protectStr = "OTHER";

            std::string typeStr;
            if (mbi.Type == MEM_IMAGE) typeStr = "模块(EXE/DLL)";
            else if (mbi.Type == MEM_PRIVATE) typeStr = "私有(堆/栈)";
            else if (mbi.Type == MEM_MAPPED) typeStr = "映射文件";
            else typeStr = "未知";

            // 【核心修改3】：64位地址很长，setw(8)不够，改成setw(16)对齐更漂亮
            std::cout << "块#" << std::dec << blockCount << " | ";
            std::cout << "基址：0x" << std::hex << std::setw(16) << (uintptr_t)mbi.BaseAddress;
            std::cout << " | 大小：0x" << std::hex << std::setw(8) << mbi.RegionSize << std::dec;
            std::cout << " | 属性：" << protectStr;
            std::cout << " | 类型：" << typeStr; // 新增了类型
            std::cout << std::endl;
        }

        current = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    }
}
int main(){
    if(!EnableDebugPrivilege()){
        system("pause");
        return 1;
    }else{ std::cout << "[*]提权成功，可以进行跨进程操作！" << std::endl; }

    std::string targetName;
    std::cout << "请输入目标进程名：";
    getline(std::cin, targetName);

    DWORD pid = GetPidByName(targetName);

    if(pid == 0){
        std::cout << "未找到进程" << targetName << "，请确认是否进程名正确！" << std::endl;
        system("pause");
        return 1;
    }
    std::cout << "找到目标进程" << targetName << " | PID：" << pid << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if(!hProcess){
        std::cerr << "[*]进程打开失败，错误码：" << GetLastError() << std::endl;
        system("pause");
        return 1;
    }

    std::cout << "\n[+] 正在扫描目标进程的内存...\n" << std::endl;
    PrintMemoryMap(hProcess);

    CloseHandle(hProcess);

    std::cout << "\n[+] 扫描完成。" << std::endl;
    system("pause");
}