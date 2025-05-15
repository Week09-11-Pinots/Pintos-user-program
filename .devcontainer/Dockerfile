# Base image: Ubuntu x86_64
FROM --platform=linux/amd64 ubuntu:18.04

ENV TZ=Asia/Seoul LANG=ko_KR.UTF-8 LANGUAGE=ko_KR.UTF-8

# Install dependencies
RUN export DEBIAN_FRONTEND=noninteractive && \
    apt-get update \
    # && echo "tzdata tzdata/Areas select Asia" | debconf-set-selections \
    # && echo "tzdata tzdata/Zones/Asia select Seoul" | debconf-set-selections \
    && apt-get install -y \
    locales tzdata \
    build-essential \
    gcc \
    gdb \
    vim \
    git \
    sudo \
    qemu-system-x86 \
    python3 \
    && locale-gen ko_KR.UTF-8 && update-locale LANG=ko_KR.UTF-8 
# && apt-get clean \
# && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash jungle && usermod -aG sudo jungle
RUN echo "jungle ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/jungle

USER jungle
WORKDIR /home/jungle

RUN echo "source /workspaces/pintos_lab_docker/pintos-kaist/activate" >> /home/jungle/.bashrc

# Clone the repository
# RUN git clone https://github.com/casys-kaist/pintos-kaist /home/jungle/pintos

# Set default shell for the `jungle` user