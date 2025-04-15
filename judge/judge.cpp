#include <iostream>
#include <string>
#include <cstdlib>
#include <regex>
#include <sstream>
#include <windows.h>
#include <sys/stat.h>
#include <TlHelp32.h>

std::string execute_and_capture_stderr(const std::string &command) {
    std::string result;
    char buffer[512];
    FILE *pipe = _popen((command + " 2>&1").c_str(), "r");
    if (!pipe) return "Failed to execute command";
    while (fgets(buffer, sizeof(buffer), pipe)) result += buffer;
    _pclose(pipe);
    return result;
}

bool compile_code(const std::string &cpp_file, const std::string &runfile, bool O2) {
    std::string command = "g++ -o " + runfile + " " + cpp_file + (O2 ? " -O2" : "");
    std::string errorMessage = execute_and_capture_stderr(command);
    if (!errorMessage.empty()) {
        std::regex file_path_regex(R"(judge/codes/[a-f0-9\-]{36}\.cpp: ?)");
        std::cerr << std::regex_replace(errorMessage, file_path_regex, "");
        return false;
    }
    return true;
}

long get_file_size(const std::string &filename) {
    struct stat stat_buf;
    return (stat(filename.c_str(), &stat_buf) == 0) ? stat_buf.st_size : -1;
}

bool restrict_process(HANDLE process, int memory_limit_mb, int time_limit_ms) {
    HANDLE job = CreateJobObject(NULL, NULL);
    if (!job) return false;

    JOBOBJECT_EXTENDED_LIMIT_INFORMATION job_info = {0};
    job_info.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
        JOB_OBJECT_LIMIT_PROCESS_MEMORY |
        JOB_OBJECT_LIMIT_JOB_MEMORY |
        JOB_OBJECT_LIMIT_PRIORITY_CLASS;

    job_info.BasicLimitInformation.ActiveProcessLimit = 1;
    job_info.BasicLimitInformation.PriorityClass = IDLE_PRIORITY_CLASS;
    job_info.ProcessMemoryLimit = memory_limit_mb * 1024ULL * 1024;
    job_info.JobMemoryLimit = memory_limit_mb * 1024ULL * 1024;

    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &job_info, sizeof(job_info)))
        return false;

    return AssignProcessToJobObject(job, process);
}

std::string run_code(const std::string &exe_path, const std::string &input_file,
                     const std::string &output_file, const std::string &error_file,
                     int time_limit_ms, int memory_limit_mb, int max_output_bytes) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    HANDLE hInput = CreateFileA(input_file.c_str(), GENERIC_READ, FILE_SHARE_READ, &sa, OPEN_EXISTING, FILE_ATTRIBUTE_READONLY, NULL);
    HANDLE hOutput = CreateFileA(output_file.c_str(), GENERIC_WRITE, 0, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    HANDLE hError  = CreateFileA(error_file.c_str(), GENERIC_WRITE, 0, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hInput == INVALID_HANDLE_VALUE || hOutput == INVALID_HANDLE_VALUE || hError == INVALID_HANDLE_VALUE)
        return "File Open Error";

    si.dwFlags |= STARTF_USESTDHANDLES;
    si.hStdInput  = hInput;
    si.hStdOutput = hOutput;
    si.hStdError  = hError;

    if (!CreateProcessA(exe_path.c_str(), NULL, NULL, NULL, TRUE,
        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        return "Execution Failed";
    }

    if (!restrict_process(pi.hProcess, memory_limit_mb, time_limit_ms)) {
        TerminateProcess(pi.hProcess, 1);
        return "Memory Limit Exceeded";
    }

    ResumeThread(pi.hThread);
    DWORD result = WaitForSingleObject(pi.hProcess, time_limit_ms);

    if (result == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 1);
        return "Time Limit Exceeded";
    }

    DWORD exitCode;
    GetExitCodeProcess(pi.hProcess, &exitCode);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hInput);
    CloseHandle(hOutput);
    CloseHandle(hError);

    // TODO: 检查 output 文件大小，超出则认为 Output Limit Exceeded
    if (get_file_size(output_file) > max_output_bytes) return "Output Limit Exceeded";

    return exitCode == 0 ? "Execution Success" : "Runtime Error";
}

int main(int argc, char *argv[]) {
    if (argc < 10) {
        std::cerr << "Usage: judge.exe <cpp_file> <input_file> <output_file> <error_file> <exe_file> <time_limit_ms> <memory_limit_mb> <max_output_bytes> [-O2]" << std::endl;
        return 1;
    }

    std::string cpp_file     = argv[1];
    std::string input_file   = argv[2];
    std::string output_file  = argv[3];
    std::string error_file   = argv[4];
    std::string exe_file     = argv[5];
    int time_limit_ms        = std::stoi(argv[6]);
    int memory_limit_mb      = std::stoi(argv[7]);
    int max_output_bytes     = std::stoi(argv[8]);
    bool use_O2              = (argc > 9 && std::string(argv[9]) == "-O2");

    if (!compile_code(cpp_file, exe_file, use_O2)) {
        std::cout << "Compilation Failed\n";
        remove(cpp_file.c_str());
        remove(input_file.c_str());
        return 1;
    }

    std::cout << "Compilation Success\n";
    std::string result = run_code(exe_file, input_file, output_file, error_file, time_limit_ms, memory_limit_mb, max_output_bytes);

    remove(exe_file.c_str());
    remove(cpp_file.c_str());
    remove(input_file.c_str());

    if (result != "Execution Success") std::cerr << result << std::endl;
    else std::cout << result << std::endl;

    return 0;
}
