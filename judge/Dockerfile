FROM gcc:13.3.0-bookworm

WORKDIR /app
RUN mkdir -p /app

COPY judge.run /app/judge.run
RUN chmod +x /app/judge.run

ENTRYPOINT ["/app/judge.run"]
