FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates dbus-x11 gnome-keyring libsecret-tools bubblewrap \
      git python3 openssh-client jq curl less procps \
 && rm -rf /var/lib/apt/lists/*
COPY akasha-linux-arm64 /usr/local/bin/akasha
RUN chmod 755 /usr/local/bin/akasha
COPY awsshim.py /usr/local/bin/aws
RUN chmod 755 /usr/local/bin/aws
COPY bootstrap.sh /bootstrap.sh
COPY seed.sh /seed.sh
RUN chmod 755 /bootstrap.sh /seed.sh
ENV HOME=/root
