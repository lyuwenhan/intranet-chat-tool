FROM gcc:13.3.0-bookworm

RUN useradd -m -u 1000 judgeuser

WORKDIR /app
RUN mkdir -p /app && chown judgeuser:judgeuser /app

COPY judge.run /app/judge.run
RUN chmod +x /app/judge.run && chown judgeuser:judgeuser /app/judge.run

USER judgeuser

ENTRYPOINT ["/app/judge.run"]
