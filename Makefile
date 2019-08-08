# Copyright (c) 2019 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

.PHONY: all build build-docker build-local fmt clean lint test vet image

IMG ?= lfedge/adam
HASH ?= $(shell git show --format=%T -s)
GOVER ?= 1.12.4-alpine3.9

# check if we should append a dirty tag
DIRTY ?= $(shell git status --short)
ifneq ($(DIRTY),)
TAG = $(HASH)-dirty
else
TAG = $(HASH)
endif

GOENV ?= GO111MODULE=on CGO_ENABLED=0
GO ?= 
ifneq ($(BUILD),local)
GO = docker run --rm -v $(PWD):/app -w /app golang:$(GOVER) env $(GOENV)
endif

GO_FILES := $(shell find . -type f -name '*.go')

all: build

bin:
	mkdir -p bin

build:
ifneq ($(BUILD),local)
	$(MAKE) build-docker
else
	$(MAKE) build-local
endif

build-local: bin
	$(GO) go build -o bin/adam main.go

build-docker: 
	docker build -t $(IMG) .

image: build-docker

ci: gitstat tag build fmt-check lint test vet image

gitstat:
	@git status

tag:
	@echo $(TAG)

fmt:
	$(GO) gofmt -w ${GO_FILES}

fmt-check:
	if [ -n "$$($(GO) gofmt -l ${GO_FILES})" ]; then \
		$(GO) gofmt -s -e -d ${GO_FILES}; \
		exit 1; \
	fi

lint: linttools
	$(GO) gometalinter --disable-all --enable=golint  --vendor ./...

vet:
	$(GO) go vet ./...

test:
	$(GO) go test ./...

linttools:
ifeq ($(BUILD),local)
ifeq (, $(shell which golint))
	$(GO) go get -u golang.org/x/lint/golint
endif
ifeq (, $(shell which gometalinter))
	$(GO) go get -u github.com/alecthomas/gometalinter
endif
endif

clean:
	rm -rf run/*

