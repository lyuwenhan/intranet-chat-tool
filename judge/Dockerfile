FROM gcc:13.3.0-bookworm

WORKDIR /app
RUN mkdir -p /app
RUN mkdir -p /ap

COPY judge.run /ap/judge.run
RUN chmod +x /ap/judge.run

ENTRYPOINT ["/ap/judge.run"]
