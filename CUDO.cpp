#include <iostream>
#include <string>
#include <vector>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#include <lm.h>
#include <tchar.h>
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "advapi32.lib")
#else
#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>
#include <cstring>
#include <sys/wait.h>
#include <termios.h>
#include <shadow.h>
#endif

// Функция для безопасного чтения пароля
std::string getPassword(const std::string& prompt = "Enter password: ") {
    std::string password;

#ifdef _WIN32
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(hStdin, &mode);
    SetConsoleMode(hStdin, mode & (~ENABLE_ECHO_INPUT));

    std::cout << prompt;
    std::getline(std::cin, password);
    std::cout << std::endl;

    SetConsoleMode(hStdin, mode);
#else
    termios oldt;
    tcgetattr(STDIN_FILENO, &oldt);
    termios newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    std::cout << prompt;
    std::getline(std::cin, password);
    std::cout << std::endl;

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif

    return password;
}

// Функция для получения списка пользователей
std::vector<std::string> getUsersList() {
    std::vector<std::string> users;

#ifdef _WIN32
    DWORD resumeHandle = 0;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    NET_API_STATUS nStatus;
    LPUSER_INFO_0 pBuf = NULL;
    LPUSER_INFO_0 pTmpBuf;

    do {
        nStatus = NetUserEnum(NULL, 0, FILTER_NORMAL_ACCOUNT,
            (LPBYTE*)&pBuf, MAX_PREFERRED_LENGTH,
            &dwEntriesRead, &dwTotalEntries, &resumeHandle);

        if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA)) {
            if ((pTmpBuf = pBuf) != NULL) {
                for (DWORD i = 0; i < dwEntriesRead; i++) {
                    if (pTmpBuf->usri0_name != NULL) {
                        // Конвертируем LPCWSTR в std::string
                        int size = WideCharToMultiByte(CP_UTF8, 0, pTmpBuf->usri0_name, -1, NULL, 0, NULL, NULL);
                        std::string username(size, 0);
                        WideCharToMultiByte(CP_UTF8, 0, pTmpBuf->usri0_name, -1, &username[0], size, NULL, NULL);
                        // Убираем нулевой символ в конце
                        if (!username.empty() && username.back() == '\0') {
                            username.pop_back();
                        }
                        users.push_back(username);
                    }
                    pTmpBuf++;
                }
            }
        }

        if (pBuf != NULL) {
            NetApiBufferFree(pBuf);
            pBuf = NULL;
        }
    } while (nStatus == ERROR_MORE_DATA);
#else
    setpwent();
    struct passwd* pw;
    while ((pw = getpwent()) != NULL) {
        if (pw->pw_uid >= 1000) {
            users.push_back(pw->pw_name);
        }
    }
    endpwent();
#endif

    std::sort(users.begin(), users.end());
    return users;
}

// Функция для запуска команды от имени пользователя
bool runAsUser(const std::string& username, const std::string& password,
    const std::string& command, const std::vector<std::string>& args) {
#ifdef _WIN32
    // Windows implementation
    HANDLE hToken;

    // Конвертируем имя пользователя в LPCWSTR
    int wusernameSize = MultiByteToWideChar(CP_UTF8, 0, username.c_str(), -1, NULL, 0);
    std::vector<wchar_t> wusernameBuffer(wusernameSize);
    MultiByteToWideChar(CP_UTF8, 0, username.c_str(), -1, wusernameBuffer.data(), wusernameSize);

    // Конвертируем пароль в LPCWSTR
    int wpasswordSize = MultiByteToWideChar(CP_UTF8, 0, password.c_str(), -1, NULL, 0);
    std::vector<wchar_t> wpasswordBuffer(wpasswordSize);
    MultiByteToWideChar(CP_UTF8, 0, password.c_str(), -1, wpasswordBuffer.data(), wpasswordSize);

    // Попытка аутентификации пользователя
    if (!LogonUserW(wusernameBuffer.data(), L".", wpasswordBuffer.data(),
        LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &hToken)) {
        std::cerr << "LogonUser failed: " << GetLastError() << std::endl;
        return false;
    }

    // Подготовка командной строки
    std::string fullCommand = command;
    for (const auto& arg : args) {
        fullCommand += " \"" + arg + "\"";
    }

    // Конвертируем команду в LPCWSTR
    int wcommandSize = MultiByteToWideChar(CP_UTF8, 0, fullCommand.c_str(), -1, NULL, 0);
    std::vector<wchar_t> wcommandBuffer(wcommandSize);
    MultiByteToWideChar(CP_UTF8, 0, fullCommand.c_str(), -1, wcommandBuffer.data(), wcommandSize);

    // Запуск процесса от имени пользователя
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    BOOL result = CreateProcessWithLogonW(wusernameBuffer.data(), L".", wpasswordBuffer.data(),
        LOGON_WITH_PROFILE, NULL, wcommandBuffer.data(), CREATE_UNICODE_ENVIRONMENT,
        NULL, NULL, &si, &pi);

    if (!result) {
        std::cerr << "CreateProcessWithLogon failed: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return false;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD exitCode;
    GetExitCodeProcess(pi.hProcess, &exitCode);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hToken);

    return exitCode == 0;

#else
    // Linux/Unix implementation
    struct passwd* userInfo = getpwnam(username.c_str());
    if (!userInfo) {
        std::cerr << "User " << username << " not found" << std::endl;
        return false;
    }

    pid_t pid = fork();
    if (pid == -1) {
        std::cerr << "Fork failed" << std::endl;
        return false;
    }

    if (pid == 0) { // Дочерний процесс
        if (setuid(userInfo->pw_uid) != 0) {
            std::cerr << "Setuid failed" << std::endl;
            exit(EXIT_FAILURE);
        }

        // Подготавливаем аргументы для execvp
        std::vector<char*> argv;
        argv.push_back(const_cast<char*>(command.c_str()));
        for (const auto& arg : args) {
            argv.push_back(const_cast<char*>(arg.c_str()));
        }
        argv.push_back(nullptr);

        execvp(command.c_str(), argv.data());

        // Если дошли сюда, execvp не удался
        std::cerr << "Exec failed for command: " << command << std::endl;
        exit(EXIT_FAILURE);
    }
    else { // Родительский процесс
        int status;
        waitpid(pid, &status, 0);
        return WIFEXITED(status) && WEXITSTATUS(status) == 0;
    }
#endif
}

void printUsage(const char* programName) {
    std::cout << "Usage: " << programName << " [options] <username> <command> [args...]\n"
        << "Options:\n"
        << "  -l, --list    List all users\n"
        << "  -p, --password Prompt for password\n"
        << "  -h, --help    Show this help message\n";
}

int main(int argc, char* argv[]) {
    bool listUsers = false;
    bool askPassword = false;
    std::string username;
    std::string command;
    std::vector<std::string> args;
    std::string password;

    // Парсинг аргументов командной строки
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-l" || arg == "--list") {
            listUsers = true;
        }
        else if (arg == "-p" || arg == "--password") {
            askPassword = true;
        }
        else if (arg == "-h" || arg == "--help") {
            printUsage(argv[0]);
            return 0;
        }
        else if (arg[0] == '-') {
            std::cerr << "Unknown option: " << arg << std::endl;
            printUsage(argv[0]);
            return 1;
        }
        else {
            // Первый не-опционный аргумент - имя пользователя
            if (username.empty()) {
                username = arg;
            }
            else if (command.empty()) {
                command = arg;
            }
            else {
                args.push_back(arg);
            }
        }
    }

    // Обработка опции --list
    if (listUsers) {
        std::cout << "System users:\n";
        auto users = getUsersList();
        for (const auto& user : users) {
            std::cout << "  " << user << std::endl;
        }
        return 0;
    }

    // Проверка обязательных аргументов
    if (username.empty() || command.empty()) {
        std::cerr << "Error: username and command are required\n";
        printUsage(argv[0]);
        return 1;
    }

    // Запрос пароля при необходимости
    if (askPassword) {
        password = getPassword("Enter password for " + username + ": ");
    }

    // Запуск команды от имени пользователя
    if (runAsUser(username, password, command, args)) {
        std::cout << "Command executed successfully" << std::endl;
        return 0;
    }
    else {
        std::cerr << "Command execution failed" << std::endl;
        return 1;
    }
}