#include <windows.h>
#include <cstring>
#include <tlhelp32.h>
#include <iostream>

int main(){
    HANDLE Tables = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(Tables == INVALID_HANDLE_VALUE){
        std::cout << "创建进程快照失败，错误码：" << GetLastError() << std::endl;
        return -1;
    }
    PROCESSENTRY32 Table;
    Table.dwSize = sizeof(PROCESSENTRY32);
    if(Process32First(Tables, &Table)){
        int SVCHOSTNUM{};
        std::string zerotierStatus = {"未检测到 ZeroTier 进程"};
        do{
            std::string TableName = Table.szExeFile;
            std::cout << TableName << std::endl;
            if(TableName == "svchost.exe"){
                SVCHOSTNUM++;
            }
            if(TableName == "zerotier_desktop_ui.exe"){
                HANDLE ZerotierKey = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, Table.th32ProcessID);
                if(ZerotierKey == NULL){
                    zerotierStatus = "获取 zerotier_desktop_ui.exe 失败！";
                }else{
                    zerotierStatus = "获取 zerotier_desktop_ui.exe 成功！";
                    CloseHandle(ZerotierKey);
                }
            }
        }while(Process32Next(Tables, &Table));
        std::cout << "svchost.exe进程数量: " << SVCHOSTNUM << std::endl;
        std::cout << zerotierStatus << std::endl;
    }else{ std::cout << "进程检索错误，请重试！" << std::endl; }
    CloseHandle(Tables);
    getchar();
}