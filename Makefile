.PHONY: all build

all: build

bin:
	mkdir -p bin

build: bin
	go build -o bin/adam main.go

fmt:
	gofmt -w $(shell find . -name '*go')
