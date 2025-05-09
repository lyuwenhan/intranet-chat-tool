compile:
g++ judge.cpp -O2 -o judge.exe

run:
Usage: judge[.exe] <cpp_file> <input_file> <output_file> <error_file> <exe_file> <time_limit_ms> <memory_limit_mb> <max_output_bytes> [-O2]

like:
judge.exe user_code.cpp input.in output.out output.err run.exe 1000 64 100000 -O2