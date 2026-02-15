# 1. Загружаем готовый образ AFL++ (он уже на базе Ubuntu/Debian и содержит все инструменты)
FROM aflplusplus/aflplusplus:latest

# 2. Устанавливаем рабочую директорию для вашего проекта
WORKDIR /app

#COPY src ./src
RUN mkdir -p /app/src

RUN mkdir -p /run/dbus #создание дирректории для dbus сокета

RUN apt update && \
    apt install -y \
    iproute2 \
    build-essential \
    libglib2.0-dev \
    libdbus-1-dev \
    pkg-config \
    libxtables-dev \
    libgnutls28-dev \
    libreadline-dev \
    libpcsclite-dev \
    libpcap-dev \
    llvm-19 llvm-19-tools \
    clang-19 \
    tcpdump \
    wireshark-common \
    isc-dhcp-client

RUN apt-get remove -y network-manager \
    && apt-get clean

RUN echo '#!/bin/bash\n\
dbus-daemon --system --nopidfile\n\
connmand -d -n\n\
exec "$@"' > /entrypoint.sh && chmod +x /entrypoint.sh

ENV CC=/usr/local/bin/afl-clang-fast
ENV CXX=/usr/local/bin/afl-clang-fast++

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/bin/bash"]