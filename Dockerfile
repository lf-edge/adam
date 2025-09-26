# Copyright (c) 2019 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

FROM lfedge/eve-alpine:15.4.0 AS build
ENV BUILD_PKGS go git
RUN eve-alpine-deploy.sh

ENV CGO_ENABLED=0
ENV GO111MODULE=on

RUN mkdir -p /adam/src && mkdir -p /adam/bin
WORKDIR /adam/src
RUN go install github.com/go-swagger/go-swagger/cmd/swagger@v0.32.3
COPY go.mod .
COPY go.sum .
RUN go mod download

# these have to be last steps so they do not bust the cache with each change
COPY . /adam/src

ARG GOOS=linux
# ARG GOARCH=amd64


RUN go build -o /out/bin/adam main.go
COPY scripts/ /out/bin/
COPY samples/ /out/adam/
RUN mkdir /adam/swaggerui
RUN /root/go/bin/swagger generate spec -o /adam/swaggerui/swagger.json


FROM scratch

COPY --from=build /out/ /
ADD swaggerui ./swaggerui/
COPY --from=build /adam/swaggerui/swagger.json ./swaggerui/swagger.json
WORKDIR /adam
ENTRYPOINT ["/bin/adam"]
