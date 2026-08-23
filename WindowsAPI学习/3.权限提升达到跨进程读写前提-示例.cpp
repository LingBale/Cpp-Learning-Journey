#include <windows.h>
#include <cstring>
#include <tlhelp32.h>
#include <iostream>

BOOL FuckExe(){
    HANDLE EXEIt;
    LUID Goit;
    if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &EXEIt)){
        std::cout << "OpenProcessToken 失败，错误码：" << GetLastError() << std::endl;
        CloseHandle(EXEIt);
        return false;
    }
    if(!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &Goit)){
        std::cout << "LookupPrivilegeValue 失败，错误码："  << GetLastError() << std::endl;
        CloseHandle(EXEIt);
        return false;
    }
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = Goit;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if(!AdjustTokenPrivileges(EXEIt, FALSE, &tp, sizeof(tp), NULL, NULL)){
        std::cout << "AdjustTokenPrivileges 失败，错误码：" << GetLastError() << std::endl;
        CloseHandle(EXEIt);
        return true;
    }
    if(GetLastError() == ERROR_NOT_ALL_ASSIGNED){
        std::cout << "警告：调试特权未能启动！" << std::endl;
        CloseHandle(EXEIt);
        return false;
    }
    CloseHandle(EXEIt);
    return true;
}
int main() {
    if (FuckExe()) {
        std::cout << "[+] 调试特权已启用，可以尝试打开系统进程了。" << std::endl;
    } else {
        std::cout << "[!] 调试特权启用失败。请确认以管理员身份运行。" << std::endl;
    }
    HANDLE Tables = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(Tables == INVALID_HANDLE_VALUE){
        std::cout << "快照获取失败，错误码：" << GetLastError() << std::endl;
        CloseHandle(Tables);
        return -1;
    }
    PROCESSENTRY32 Table;
    Table.dwSize = sizeof(PROCESSENTRY32);
    if(Process32First(Tables, &Table)){
        std::string QQPCMgrcIT = "没有查询到QQPCMgr.exe，请确保电脑有此进程";
        do{
            std::string TableName = Table.szExeFile;
            std::cout << TableName << std::endl;
            if(TableName == "QQPCMgr.exe"){
                HANDLE QQPCMgrc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, Table.th32ProcessID);
                if(QQPCMgrc != NULL){
                    QQPCMgrcIT = "获取QQPCMgr.exe进程成功！";
                }else{
                    QQPCMgrcIT = "获取QQPCMgr.exe进程失败！";
                }
            }
        }while(Process32Next(Tables, &Table));
        std::cout << QQPCMgrcIT << std::endl;
    }else{std::cout << "进程遍历失败，错误码：" << GetLastError() << std::endl;}
    CloseHandle(Tables);
    getchar();
}