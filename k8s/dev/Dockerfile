FROM gcr.io/istio-testing/build-tools:master-2020-05-20T22-13-03

RUN curl -fsSL https://code-server.dev/install.sh > /tmp/install.sh && \
    sh /tmp/install.sh

RUN apt update && apt install -y net-tools sudo lsof netcat tcpdump iptables iproute2

RUN useradd -u 1000 -U -d /work -s /bin/bash build && \
     usermod -G users build && \
      echo "build ALL=NOPASSWD: ALL" >> /etc/sudoers

RUN apt-get clean && \
     rm -rf \
    	/tmp/* \
    	/var/lib/apt/lists/* \
    	/var/tmp/*

ENV GO111MODULE=on
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOPROXY=https://proxy.golang.org
ENV HOME=/work
WORKDIR /work
