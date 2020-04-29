# Copyright (c) 2019 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

FROM golang:1.12.5-alpine3.9 AS build

ENV CGO_ENABLED=0
ENV GO111MODULE=on

RUN apk --update add git

RUN mkdir -p /adam/src && mkdir -p /adam/bin
WORKDIR /adam/src
COPY go.mod .
COPY go.sum .
RUN go mod download

# these have to be last steps so they do not bust the cache with each change
COPY . /adam/src

ARG GOOS=linux
ARG GOARCH=amd64

RUN go build -o /adam/bin/adam main.go

FROM alpine:3.11

COPY scripts /bin
COPY samples /adam
COPY --from=build /adam/bin/adam /bin/
WORKDIR /adam
ENTRYPOINT ["/bin/adam"]
