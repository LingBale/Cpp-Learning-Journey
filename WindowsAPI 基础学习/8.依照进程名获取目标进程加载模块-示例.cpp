#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>

#pragma comment(lib, "psapi.lib");

// 提权，确保能打开目标进程
bool EnableDebugPrivilege(){
    HANDLE hToken;
    if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)){ return 1; }
    LUID luid;
    if(!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)){ 
        CloseHandle(hToken);
        return 1; }
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    bool success = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    if(GetLastError() == ERROR_NOT_ALL_ASSIGNED){
        CloseHandle(hToken);
        return 1; }
    CloseHandle(hToken);
    return success;
}
// 根据进程名获取 PID
DWORD GetPidByName(const std::string& targetName){
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if(Process32First(hSnap, &pe)){
        do{
            if(pe.szExeFile == targetName){
                CloseHandle(hSnap);
                return pe.th32ProcessID;}
        }while(Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return 0;
}
// 模块枚举函数
void ListModulesForProcess(DWORD pid){
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if(!hProcess){
        std::cerr << "[-] 进程打开失败，错误码：" << GetLastError() << std::endl;
        return; }
    std::vector<HMODULE> modules(1024);
    DWORD needed;
    if(!EnumProcessModules(hProcess, modules.data(), modules.size() * sizeof(HMODULE), &needed)){
    std::cerr << "[-] EnumProcessModules失败，错误码：" << GetLastError() << std::endl;
    CloseHandle(hProcess);
    return; }

    size_t moduleCount = needed / sizeof(HMODULE);
    std::cout << "[+] 共找到" << moduleCount << "个模块！" << std::endl;
    std::cout << "======================================================" << std::endl;

    for(size_t i = 0; i < moduleCount; i++){
        HMODULE hMod = modules[i];
        
        // 获取模块名字
        char szName[MAX_PATH];
        if(GetModuleBaseNameA(hProcess, hMod, szName, MAX_PATH) == 0){ strcpy_s(szName, "<未知>"); }
    
        // 获取模块路径
        char path[MAX_PATH];
        if(GetModuleFileNameExA(hProcess, hMod, path, MAX_PATH) == 0){ strcpy_s(path, "<无法获取路径>"); }
    
        // 获取模块详细信息
        MODULEINFO modInfo;
        if(!GetModuleInformation(hProcess, hMod, &modInfo, sizeof(MODULEINFO))){
            std::cerr << "[-] 获取模块信息失败：" << szName << std::endl;
            continue;
        }

        std::cout << "[" << i << "]" << szName << std::endl;
        std::cout << "     基址：" << std::hex << std::setw(16) << std::setfill('0') 
                  << (uintptr_t)modInfo.lpBaseOfDll << std::dec << std::endl;
        std::cout << "     大小：" << std::hex << modInfo.SizeOfImage << std::dec << "字节" << std::endl;
        std::cout << "     路径：" << path << std::endl;
        std::cout << "----------------------------------------" << std::endl;
    }
    CloseHandle(hProcess);
}
// 主函数
int main(){
    if(!EnableDebugPrivilege()){ std::cerr << "[-] 提权失败，请以管理员身份运行。" << std::endl; }
    else{ std::cerr << "[+] 提权成功，可以操作其他进程了。" << std::endl; }

    std::string targetProcessName;
    std::cout << "请输入目标进程名（例如: notepad.exe）: ";
    getline(std::cin, targetProcessName);
    std::cout << "[*] 正在查找进程: " << targetProcessName << std::endl;
    
    DWORD pid = GetPidByName(targetProcessName);
    if(pid == 0){
        std::cerr << "[-] 未找到进程: " << targetProcessName << std::endl;
        return 1;}
    std::cout << "[+] 找到进程，PID: " << pid << std::endl;
    ListModulesForProcess(pid);

    system("pause");
}
