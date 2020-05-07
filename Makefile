# Copyright (c) 2019 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

.PHONY: all build build-docker fmt clean lint test vet image

IMG ?= lfedge/adam
HASH ?= $(shell git show --format=%T -s)
GOVER ?= 1.14.2-alpine3.11

# check if we should append a dirty tag
DIRTY ?= $(shell git status --short)
ifneq ($(DIRTY),)
TAG = $(HASH)-dirty
else
TAG = $(HASH)
endif

# BUILDARCH is the host architecture
# ARCH is the target architecture
# we need to keep track of them separately
BUILDARCH ?= $(shell uname -m)
BUILDOS ?= $(shell uname -s | tr A-Z a-z)

# canonicalized names for host architecture
ifeq ($(BUILDARCH),aarch64)
BUILDARCH=arm64
endif
ifeq ($(BUILDARCH),x86_64)
BUILDARCH=amd64
endif

# unless otherwise set, I am building for my own architecture, i.e. not cross-compiling
# and for my OS
ARCH ?= $(BUILDARCH)
OS ?= $(BUILDOS)

# canonicalized names for target architecture
ifeq ($(ARCH),aarch64)
        override ARCH=arm64
endif
ifeq ($(ARCH),x86_64)
    override ARCH=amd64
endif

BINDIR := bin
BIN := adam
LOCALBIN := $(BINDIR)/$(BIN)-$(OS)-$(ARCH)
LOCALLINK := $(BINDIR)/$(BIN)

GOENV ?= GOOS=$(OS) GOARCH=$(ARCH) GO111MODULE=on CGO_ENABLED=0
GO ?= $(GOENV)
ifneq ($(BUILD),local)
GO = docker run --rm -v $(PWD):/app -w /app golang:$(GOVER) env $(GOENV)
endif

GO_FILES := $(shell find . -type f -name '*.go')

all: build

$(BINDIR):
	mkdir -p $@

build: bin $(LOCALBIN) $(LOCALLINK)
$(LOCALBIN):
	$(GO) go build -o $@ main.go

$(LOCALLINK):
	@if [ "$(OS)" = "$(BUILDOS)" -a "$(ARCH)" = "$(BUILDARCH)" -a ! -L "$@" -a ! -e "$@" ]; then ln -s $(notdir $(LOCALBIN)) $@; fi

build-docker: 
	docker build -t $(IMG) .

build-docker-local: build
	docker build -t $(IMG) -f Dockerfile.local .

image-local: build-docker-local

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

