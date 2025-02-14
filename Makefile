.PHONY: all hive run
all: hive
hive:
	ARCH=$(shell uname -m) go generate ./cmd
	go build -o hive ./cmd

run:
	sudo ./hive
