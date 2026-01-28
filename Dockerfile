FROM ubuntu:24.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Set locale and terminal
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8
ENV TERM=xterm-256color

# Install dependencies
RUN apt-get update && apt-get install -y \
    curl \
    git \
    ca-certificates \
    gnupg \
    wget \
    build-essential \
    gcc \
    g++ \
    gdb \
    make \
    cmake \
    clang \
    tcc \
    software-properties-common \
    locales \
    sudo \
    direnv \
    ruby-full \
    ruby-bundler \
    && rm -rf /var/lib/apt/lists/*

# Install Python latest (via deadsnakes PPA for latest version)
RUN add-apt-repository ppa:deadsnakes/ppa -y \
    && apt-get update \
    && apt-get install -y \
    python3.14 \
    python3.14-venv \
    python3.14-dev \
    python3-pip \
    && update-alternatives --install /usr/bin/python python /usr/bin/python3.14 1 \
    && update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.14 1 \
    && rm -rf /var/lib/apt/lists/*

# Install Go latest (1.25.x)
ENV GO_VERSION=1.25.5
RUN wget -q https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz \
    && rm go${GO_VERSION}.linux-amd64.tar.gz

# Install Node.js 24.x LTS (Krypton)
RUN curl -fsSL https://deb.nodesource.com/setup_24.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# Install Claude Code globally
RUN npm install -g @anthropic-ai/claude-code

# Create claude user with sudo access (UID 1000 to match typical host user)
# First remove any existing user with UID 1000, then create claude user
RUN existing_user=$(getent passwd 1000 | cut -d: -f1) \
    && if [ -n "$existing_user" ]; then userdel -r "$existing_user" 2>/dev/null || true; fi \
    && useradd -m -s /bin/bash -u 1000 claude \
    && echo "claude ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Set up environment variables for claude user
ENV HOME=/home/claude
ENV USER=claude

# Go environment
ENV GOROOT=/usr/local/go
ENV GOPATH=/home/claude/go
ENV GOBIN=/home/claude/go/bin

# Python environment
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PIP_USER=1
ENV PYTHONUSERBASE=/home/claude/.local

# Node.js environment
ENV NPM_CONFIG_PREFIX=/home/claude/.npm-global

# Ruby/Bundler environment
ENV GEM_HOME=/home/claude/.gem
ENV BUNDLE_PATH=/home/claude/.bundle

# Combined PATH with all tools
ENV PATH=/home/claude/.local/bin:/home/claude/.npm-global/bin:/home/claude/.gem/bin:/home/claude/go/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Switch to claude user
USER claude
WORKDIR /home/claude

# Set up directories and shell configuration
RUN mkdir -p \
    /home/claude/workspace \
    /home/claude/go/bin \
    /home/claude/go/pkg \
    /home/claude/go/src \
    /home/claude/.local/bin \
    /home/claude/.npm-global \
    /home/claude/.gem \
    /home/claude/.bundle \
    /home/claude/.config

# Create .bashrc with all environment variables
RUN echo '# Environment variables' >> /home/claude/.bashrc \
    && echo 'export LANG=C.UTF-8' >> /home/claude/.bashrc \
    && echo 'export LC_ALL=C.UTF-8' >> /home/claude/.bashrc \
    && echo 'export TERM=xterm-256color' >> /home/claude/.bashrc \
    && echo '' >> /home/claude/.bashrc \
    && echo '# Go' >> /home/claude/.bashrc \
    && echo 'export GOROOT=/usr/local/go' >> /home/claude/.bashrc \
    && echo 'export GOPATH=$HOME/go' >> /home/claude/.bashrc \
    && echo 'export GOBIN=$HOME/go/bin' >> /home/claude/.bashrc \
    && echo '' >> /home/claude/.bashrc \
    && echo '# Python' >> /home/claude/.bashrc \
    && echo 'export PYTHONDONTWRITEBYTECODE=1' >> /home/claude/.bashrc \
    && echo 'export PYTHONUNBUFFERED=1' >> /home/claude/.bashrc \
    && echo 'export PIP_USER=1' >> /home/claude/.bashrc \
    && echo 'export PYTHONUSERBASE=$HOME/.local' >> /home/claude/.bashrc \
    && echo '' >> /home/claude/.bashrc \
    && echo '# Node.js' >> /home/claude/.bashrc \
    && echo 'export NPM_CONFIG_PREFIX=$HOME/.npm-global' >> /home/claude/.bashrc \
    && echo '' >> /home/claude/.bashrc \
    && echo '# Ruby/Bundler' >> /home/claude/.bashrc \
    && echo 'export GEM_HOME=$HOME/.gem' >> /home/claude/.bashrc \
    && echo 'export BUNDLE_PATH=$HOME/.bundle' >> /home/claude/.bashrc \
    && echo '' >> /home/claude/.bashrc \
    && echo '# PATH' >> /home/claude/.bashrc \
    && echo 'export PATH=$HOME/.local/bin:$HOME/.npm-global/bin:$HOME/.gem/bin:$HOME/go/bin:/usr/local/go/bin:$PATH' >> /home/claude/.bashrc \
    && echo '' >> /home/claude/.bashrc \
    && echo '# Aliases' >> /home/claude/.bashrc \
    && echo 'alias ll="ls -la"' >> /home/claude/.bashrc \
    && echo 'alias py="python"' >> /home/claude/.bashrc \
    && echo '' >> /home/claude/.bashrc \
    && echo '# direnv' >> /home/claude/.bashrc \
    && echo 'eval "$(direnv hook bash)"' >> /home/claude/.bashrc

# Also create .profile for login shells
RUN cp /home/claude/.bashrc /home/claude/.profile

WORKDIR /home/claude/workspace

RUN git config --global user.email "realorko@nowhere.com"
RUN git config --global user.name "realorko"


# Default command with dangerously-skip-permissions flag
CMD ["claude", "--dangerously-skip-permissions"]
