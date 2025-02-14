FROM alpine:latest
WORKDIR /app
COPY ./* /app/
RUN chmod +x /app/hive
CMD ["/app/hive"]
