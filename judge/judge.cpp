#include <iostream>
#include <string>
#include <cstdlib>
#include <regex>
#include <sstream>
#include <windows.h>
#include <sys/stat.h>

// 运行 `g++` 并捕获错误输出
std::string execute_and_capture_stderr(const std::string &command) {
    std::string result;
    char buffer[512];

    FILE *pipe = _popen((command + " 2>&1").c_str(), "r");
    if (!pipe) return "Failed to execute command";

    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
    }
    _pclose(pipe);

    return result;
}

// 编译代码，去掉 `judge/codes/uuid.cpp` 路径
bool compile_code(const std::string &cpp_file, const std::string &runfile, bool O2) {
    std::string command = "g++ -o " + runfile + " " + cpp_file + (O2 ? " -O2" : "");
    
    // 捕获 `g++` 编译错误
    std::string errorMessage = execute_and_capture_stderr(command);

    if (!errorMessage.empty()) {
        // **使用新的正则匹配 `judge/codes/uuid.cpp`**
        std::regex file_path_regex(R"(judge/codes/[a-f0-9\-]{36}\.cpp: ?)");
        std::string cleanedError = std::regex_replace(errorMessage, file_path_regex, "");

        std::cerr << cleanedError; // 仅输出错误信息
        return false;
    }

    return true;
}

// 获取文件大小
long get_file_size(const std::string &filename) {
	struct stat stat_buf;
	if (stat(filename.c_str(), &stat_buf) == 0) {
		return stat_buf.st_size;
	}
	return -1;  // 获取失败
}

// 限制子进程创建
bool restrict_subprocess_creation(HANDLE process, int memory_limit_mb) {
	HANDLE job = CreateJobObject(NULL, NULL);
	if (job == NULL) return false;

	JOBOBJECT_EXTENDED_LIMIT_INFORMATION job_info;
	ZeroMemory(&job_info, sizeof(job_info));

	// 限制子进程数为 1
	job_info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
	job_info.BasicLimitInformation.ActiveProcessLimit = 1;

	// 限制内存使用
	job_info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
	job_info.JobMemoryLimit = memory_limit_mb * 1024 * 1024; // MB 转换为字节

	return SetInformationJobObject(job, JobObjectExtendedLimitInformation, &job_info, sizeof(job_info)) &&
		   AssignProcessToJobObject(job, process);
}

// 运行受限的用户代码
std::string run_untrusted_code(const std::string &exe_path, const std::string &input_file,
							   const std::string &output_file, const std::string &error_file,
							   int time_limit_ms, int memory_limit_mb, int max_output_bytes) {
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	SECURITY_ATTRIBUTES sa;
	HANDLE hInput, hOutput, hError;

	ZeroMemory(&si, sizeof(si));
	ZeroMemory(&pi, sizeof(pi));
	ZeroMemory(&sa, sizeof(sa));
	si.cb = sizeof(si);
	sa.nLength = sizeof(sa);
	sa.bInheritHandle = TRUE;
	sa.lpSecurityDescriptor = NULL;

	hInput = CreateFileA(input_file.c_str(), GENERIC_READ, FILE_SHARE_READ, &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	hOutput = CreateFileA(output_file.c_str(), GENERIC_WRITE, FILE_SHARE_WRITE, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	hError = CreateFileA(error_file.c_str(), GENERIC_WRITE, FILE_SHARE_WRITE, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hInput == INVALID_HANDLE_VALUE || hOutput == INVALID_HANDLE_VALUE || hError == INVALID_HANDLE_VALUE) {
		return "Runtime Error";
	}

	si.hStdInput = hInput;
	si.hStdOutput = hOutput;
	si.hStdError = hError;
	si.dwFlags |= STARTF_USESTDHANDLES;

	if (!CreateProcessA(exe_path.c_str(), NULL, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		return "Runtime Error";
	}

	if (!restrict_subprocess_creation(pi.hProcess, memory_limit_mb)) {
		return "Memory Limit Exceeded";
	}

	ResumeThread(pi.hThread);
	DWORD waitResult = WaitForSingleObject(pi.hProcess, time_limit_ms);

	if (waitResult == WAIT_TIMEOUT) {
		TerminateProcess(pi.hProcess, 1);
		return "Time Limit Exceeded";
	}

	DWORD exit_code;
	GetExitCodeProcess(pi.hProcess, &exit_code);

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	CloseHandle(hInput);
	CloseHandle(hOutput);
	CloseHandle(hError);

	return (exit_code == 0) ? "Execution Finished Successfully" : "Runtime Error";
}

int main(int argc, char *argv[]) {
	if (argc < 10) {
		std::cerr << "Usage: judge.exe <cpp_file> <input_file> <output_file> <error_file> <run_file> <time_limit_ms> <memory_limit_mb> <max_output_bytes> [-O2]" << std::endl;
		return 1;
	}

	std::string cpp_file = argv[1];
	std::string input_file = argv[2];
	std::string output_file = argv[3];
	std::string error_file = argv[4];
	std::string runfile = argv[5];
	int time_limit_ms = std::stoi(argv[6]);
	int memory_limit_mb = std::stoi(argv[7]);
	int max_output_bytes = std::stoi(argv[8]);
	bool O2 = (argc > 9 && std::string(argv[9]) == "-O2");

	if (!compile_code(cpp_file, runfile, O2)) {
		std::cout << "Compilation Failed" << std::endl;
		remove(cpp_file.c_str());
		remove(input_file.c_str());
		return 1;
	}
	std::cout << "Compilation Success" << std::endl;

	std::string result = run_untrusted_code(runfile, input_file, output_file, error_file, time_limit_ms, memory_limit_mb, max_output_bytes);
	remove(runfile.c_str());
	remove(cpp_file.c_str());
	remove(input_file.c_str());
	if(result != "Execution Finished Successfully"){
		std::cerr << result << std::endl;
	}else{
		std::cout << result << std::endl;
	}


	return 0;
}
