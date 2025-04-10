# syntax=docker/dockerfile:1.4
FROM --platform=$TARGETPLATFORM docker.io/golang:1.24-bookworm AS builder

ARG VER=devel
ARG BUILDTAGS=""
ARG EXTERNAL="0"

ENV CGO_ENABLED=0

RUN mkdir -p /sshpiperd/plugins
WORKDIR /app

# Initialize and update submodules (recursive)
COPY . .
RUN git config --global --add safe.directory /app
RUN git submodule update --init --recursive

RUN --mount=type=cache,target=/root/.cache/go-build \
    go build -tags "$BUILDTAGS" -ldflags "-X main.mainver=$VER" -o /sshpiperd ./cmd/...
RUN --mount=type=cache,target=/root/.cache/go-build \
    go build -tags "$BUILDTAGS" -o /sshpiperd/plugins ./plugin/...
COPY entrypoint.sh /sshpiperd

FROM builder AS testrunner
RUN apt update && apt install -y autoconf automake libssl-dev libz-dev

COPY --from=farmer1992/openssh-static:V_9_8_P1 /usr/bin/ssh /usr/bin/ssh-9.8p1
COPY --from=farmer1992/openssh-static:V_8_0_P1 /usr/bin/ssh /usr/bin/ssh-8.0p1

FROM docker.io/busybox
# LABEL maintainer="Boshi Lian<farmer1992@gmail.com>"

RUN mkdir -p /etc/ssh/

# Add user nobody with id 1
ARG USERID=1000
ARG GROUPID=1000
RUN addgroup -g $GROUPID -S sshpiperd && adduser -u $USERID -S sshpiperd -G sshpiperd

# Add execution rwx to user 1
RUN chown -R $USERID:$GROUPID /etc/ssh/

USER $USERID:$GROUPID

COPY --from=builder --chown=$USERID:$GROUPID /sshpiperd/ /sshpiperd
EXPOSE 2222

ENTRYPOINT ["/sshpiperd/entrypoint.sh"]
