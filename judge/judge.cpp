#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <regex>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <sys/stat.h>

#ifdef _WIN32
#include <windows.h>
#include <TlHelp32.h>
static HANDLE global_job = NULL;
#else
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/prctl.h>
#endif

long get_file_size(const std::string &filename) {
    struct stat stat_buf;
    return (stat(filename.c_str(), &stat_buf) == 0) ? stat_buf.st_size : -1;
}

std::string execute_and_capture_stderr(const std::string &command) {
    std::string result;
    char buffer[512];
#ifdef _WIN32
    FILE *pipe = _popen((command + " 2>&1").c_str(), "r");
#else
    FILE *pipe = popen((command + " 2>&1").c_str(), "r");
#endif
    if (!pipe) return "Failed to execute command";
    while (fgets(buffer, sizeof(buffer), pipe)) result += buffer;
#ifdef _WIN32
    _pclose(pipe);
#else
    pclose(pipe);
#endif
    return result;
}

bool compile_code(const std::string &cpp_file, const std::string &runfile, bool use_O2) {
    std::string command = "g++ -o " + runfile + " " + cpp_file + (use_O2 ? " -O2" : "");
    std::string errorMessage = execute_and_capture_stderr(command);
    if (!errorMessage.empty()) {
        std::regex file_path_regex(R"(judge/codes/[a-f0-9\-]{36}\.cpp: ?)");
        std::cerr << std::regex_replace(errorMessage, file_path_regex, "");
        return false;
    }
    return true;
}

#ifdef _WIN32

bool restrict_process(HANDLE process, int memory_limit_mb, int /*time_limit_ms*/) {
    if (!global_job) {
        global_job = CreateJobObject(NULL, NULL);
        if (!global_job) return false;

        JOBOBJECT_EXTENDED_LIMIT_INFORMATION job_info = {0};
        job_info.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
            JOB_OBJECT_LIMIT_PROCESS_MEMORY |
            JOB_OBJECT_LIMIT_JOB_MEMORY |
            JOB_OBJECT_LIMIT_PRIORITY_CLASS |
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

        job_info.BasicLimitInformation.ActiveProcessLimit = 1;
        job_info.BasicLimitInformation.PriorityClass = IDLE_PRIORITY_CLASS;
        job_info.ProcessMemoryLimit = memory_limit_mb * 1024ULL * 1024;
        job_info.JobMemoryLimit = memory_limit_mb * 1024ULL * 1024;

        if (!SetInformationJobObject(global_job, JobObjectExtendedLimitInformation, &job_info, sizeof(job_info))) {
            CloseHandle(global_job);
            global_job = NULL;
            return false;
        }
    }

    return AssignProcessToJobObject(global_job, process);
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

    if (get_file_size(output_file) > max_output_bytes)
        return "Output Limit Exceeded";

    return exitCode == 0 ? "Execution Success" : "Runtime Error";
}

#else // Linux

void set_limits(int time_limit_sec, int memory_limit_mb, int output_limit_bytes) {
    struct rlimit r;
    r.rlim_cur = r.rlim_max = time_limit_sec;
    setrlimit(RLIMIT_CPU, &r);
    r.rlim_cur = r.rlim_max = memory_limit_mb * 1024ULL * 1024;
    setrlimit(RLIMIT_AS, &r);
    r.rlim_cur = r.rlim_max = output_limit_bytes;
    setrlimit(RLIMIT_FSIZE, &r);
}

std::string run_code(const std::string &exe_path, const std::string &input_file,
                     const std::string &output_file, const std::string &error_file,
                     int time_limit_ms, int memory_limit_mb, int max_output_bytes) {
    pid_t pid = fork();
    if (pid < 0) return "Fork Failed";
    if (pid == 0) {
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        int in_fd  = open(input_file.c_str(), O_RDONLY);
        int out_fd = open(output_file.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
        int err_fd = open(error_file.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (in_fd < 0 || out_fd < 0 || err_fd < 0) exit(101);
        dup2(in_fd, 0); dup2(out_fd, 1); dup2(err_fd, 2);
        close(in_fd); close(out_fd); close(err_fd);
        set_limits((time_limit_ms + 999) / 1000, memory_limit_mb, max_output_bytes);
        execl(exe_path.c_str(), exe_path.c_str(), nullptr);
        exit(102);
    }

    int status = 0, waited = 0;
    while (waited < time_limit_ms) {
        usleep(10000); waited += 10;
        pid_t ret = waitpid(pid, &status, WNOHANG);
        if (ret == pid) break;
    }

    if (waited >= time_limit_ms) {
        kill(pid, SIGKILL);
        return "Time Limit Exceeded";
    }

    if (WIFEXITED(status)) {
        int exitCode = WEXITSTATUS(status);
        if (exitCode == 0) {
            if (get_file_size(output_file) > max_output_bytes)
                return "Output Limit Exceeded";
            return "Execution Success";
        } else {
            return "Runtime Error";
        }
    }

    return "Abnormal Termination";
}

#endif

int main(int argc, char *argv[]) {
    if (argc < 10) {
        std::cerr << "Usage: judge[.exe] <cpp_file> <input_file> <output_file> <error_file> <exe_file> <time_limit_ms> <memory_limit_mb> <max_output_bytes> [-O2]\n";
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
        return 1;
    }

    std::cout << "Compilation Success\n";
    std::string result = run_code(exe_file, input_file, output_file, error_file, time_limit_ms, memory_limit_mb, max_output_bytes);

    if (result != "Execution Success") std::cerr << result << std::endl;
    else std::cout << result << std::endl;
	#ifdef _WIN32
	if (global_job) CloseHandle(global_job); // ✅ 释放 Job 对象资源
	#endif
    return 0;
}
