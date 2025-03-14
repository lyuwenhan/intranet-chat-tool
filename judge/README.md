compile:
g++ judge.cpp -O2 -o judge.exe

run:
judge.exe user_code.cpp input.in output.out output.err runfile.exe time(ms) memory(mb) [-O2]
  like:
  judge.exe user_code.cpp input.in output.out output.err run.exe 1000 64 -O2