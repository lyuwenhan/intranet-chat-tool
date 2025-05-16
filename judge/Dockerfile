FROM gcc:13.3.0-bookworm

# 创建工作目录
WORKDIR /app

# 拷贝评测主程序（judge.out 或 judge.cpp）
COPY judge.run /app/judge.run

# 授予执行权限
RUN chmod +x /app/judge.run

# 默认执行命令（实际运行时会被 override）
ENTRYPOINT ["/app/judge.run"]
