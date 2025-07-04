#include "Memory/Memory.hpp"
#include <iostream>

struct YaraResult {
    int ReaderCount;
    int SCAN_BAD_CERT;
    int SCAN_NEUTRAL;
    int SCAN_SUSPICIOUS;
    int SCAN_LIKELY_MALICIOUS;
    int SCAN_MALICIOUS;
};

void MoveCursorToTop()
{
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    COORD cursorPos = { 0, 0 };
    SetConsoleCursorPosition(hConsole, cursorPos);
}

int main()
{
    SetConsoleTitle("Yara Detection Reader - 0x108 & Bytecode ;) - version-9bf2d7ce6a0345d5");

    pid = GetPID("Roblox");
    if (!pid) {
        std::cerr << "Roblox not found\n";
        getchar();
        exit(0);
    }

    pHandle = OpenProcess(PROCESS_VM_READ, 0, pid);
    uintptr_t hyperionBase = GetModuleBaseAddress("RobloxPlayerBeta.dll");


    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SMALL_RECT windowSize = { 0, 0, 30, 6 };
    SetConsoleWindowInfo(hConsole, TRUE, &windowSize);

    SetWindowPos(GetConsoleWindow(), HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);

    CONSOLE_CURSOR_INFO cursorInfo;
    GetConsoleCursorInfo(hConsole, &cursorInfo);
    cursorInfo.bVisible = FALSE;
    SetConsoleCursorInfo(hConsole, &cursorInfo);
    while (true) {
        YaraResult results = Read<YaraResult>(hyperionBase + 0x2B87EC); 
        MoveCursorToTop();

        std::cout << "SCAN_BAD_CERT = " << results.SCAN_BAD_CERT << "          \n";
        std::cout << "SCAN_NEUTRAL = " << results.SCAN_NEUTRAL << "            \n";
        std::cout << "SCAN_SUSPICIOUS = " << results.SCAN_SUSPICIOUS << "      \n";
        std::cout << "SCAN_LIKELY_MALICIOUS = " << results.SCAN_LIKELY_MALICIOUS << "   \n";
        std::cout << "SCAN_MALICIOUS = " << results.SCAN_MALICIOUS << "         \n";

        Sleep(100);
    }
}
