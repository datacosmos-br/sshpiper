FROM docker.io/golang:1.24-bookworm as builder

ARG VER=devel
ARG EXTERNAL="0"

ENV CGO_ENABLED=0

RUN mkdir -p /sshpiperd/plugins
WORKDIR /app
RUN curl -fsSL https://go.dev/dl/go1.23.4.linux-amd64.tar.gz -o /tmp/go1.23.linux-amd64.tar.gz
RUN tar -C /usr/local -xzf /tmp/go1.23.linux-amd64.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}"
RUN go version

# Initialize and update submodules (recursive)
COPY . .
RUN git config --global --add safe.directory '/app'
RUN git submodule init
# Ensure submodules are properly initialized and updated (including recursive)
RUN git submodule update

RUN  go build -o /sshpiperd -ldflags "-X main.mainver=$VER" ./cmd/... 
RUN  go build -o /sshpiperd/plugins  ./plugin/...
ADD entrypoint.sh /sshpiperd

FROM builder AS testrunner
RUN apt update && apt install -y autoconf automake libssl-dev libz-dev

COPY --from=farmer1992/openssh-static:V_9_8_P1 /usr/bin/ssh /usr/bin/ssh-9.8p1
COPY --from=farmer1992/openssh-static:V_8_0_P1 /usr/bin/ssh /usr/bin/ssh-8.0p1

FROM docker.io/busybox
# LABEL maintainer="Boshi Lian<farmer1992@gmail.com>"

RUN mkdir /etc/ssh/

# Add user nobody with id 1
ARG USERID=1000
ARG GROUPID=1000
RUN addgroup -g $GROUPID -S sshpiperd && adduser -u $USERID -S sshpiperd -G sshpiperd

# Add execution rwx to user 1
RUN chown -R $USERID:$GROUPID /etc/ssh/

USER $USERID:$GROUPID

COPY --from=builder --chown=$USERID /sshpiperd/ /sshpiperd
EXPOSE 2222

ENTRYPOINT ["/sshpiperd/entrypoint.sh"]