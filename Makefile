.PHONY: all build build-docker build-local fmt clean

IMG ?= zededa/adam

all: build

bin:
	mkdir -p bin

build: build-docker

build-local: bin
	CGO_ENABLED=0 GO111MODULE=on go build -o bin/adam main.go

build-docker: 
	docker build -t $(IMG) .

fmt:
	gofmt -w $(shell find . -name '*go')

clean:
	rm -rf run/*

