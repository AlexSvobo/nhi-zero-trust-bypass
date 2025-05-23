# docker/bind-vulnerable-build/Dockerfile

# Use a stable Debian base image
FROM debian:bookworm-slim

LABEL maintainer="Your Name <your.email@example.com>"
LABEL description="BIND 9.20.8 built from source for CVE-2025-40775 testing"

ENV BIND_VERSION=9.20.8
ENV TZ=America/New_York
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Disable interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies and necessary runtime libraries
# libcap-dev for network capabilities, openssl, libtool for build, curl for download
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    liburcu-dev \
    libuv1-dev \
    libcap-dev \
    libtool \
    pkg-config \
    curl \
    dnsutils \
    iputils-ping \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create user and group for named
RUN groupadd -r named && useradd -r -g named -s /sbin/nologin -d /var/cache/bind named

# Create necessary directories
RUN mkdir -p /etc/bind \
    /var/cache/bind \
    /var/lib/bind \
    /var/log/bind \
    /var/run/named \
    && chown -R named:named /var/cache/bind /var/lib/bind /var/log/bind /var/run/named \
    && chmod 775 /var/cache/bind /var/lib/bind /var/log/bind /var/run/named


WORKDIR /tmp/bind-src

# Download BIND source - using .tar.xz
RUN curl -f -o bind-${BIND_VERSION}.tar.xz https://ftp.isc.org/isc/bind9/${BIND_VERSION}/bind-${BIND_VERSION}.tar.xz \
    && tar xJf bind-${BIND_VERSION}.tar.xz \
    && mv bind-${BIND_VERSION} /usr/src/bind-${BIND_VERSION} \
    && rm bind-${BIND_VERSION}.tar.xz

WORKDIR /usr/src/bind-${BIND_VERSION}

# Configure, compile, and install BIND
# --with-libtool ensures libtool is used correctly
# --enable-dnstap=no to simplify build, if not needed
# --sysconfdir sets config file location
# --localstatedir sets cache/runtime data location
# --with-openssl to link against openssl
RUN ./configure \
    --prefix=/usr \
    --sysconfdir=/etc/bind \
    --localstatedir=/var \
    --enable-shared \
    --with-libtool \
    --with-openssl \
    --disable-linux-caps \
    --with-pic \
    --without-gssapi \
    --without-lmdb \
    --without-json \
    --without-libxml2 \
    --without-dlz-mysql \
    --without-dlz-postgres \
    --without-dlz-sqlite3 \
    --without-dlz-ldap \
    --without-dlz-stub \
    --without-dlz-filesystem \
    --disable-doh \
    && make -j$(nproc) \
    && make install

# Clean up build dependencies and source
RUN apt-get remove -y build-essential libssl-dev libcap-dev libtool pkg-config curl \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /usr/src/bind-${BIND_VERSION} /tmp/bind-src

# Copy your named.conf and named.ca into the image
# IMPORTANT: These files MUST be placed in docker/bind-vulnerable-build/config/
# before building the image.
COPY ./config/named.conf /etc/bind/named.conf
COPY ./config/named.ca /etc/bind/named.ca

# Ensure proper ownership for config files
RUN chown named:named /etc/bind/named.conf \
    && chmod 644 /etc/bind/named.conf \
    && chown named:named /etc/bind/named.ca \
    && chmod 644 /etc/bind/named.ca

EXPOSE 53/udp 53/tcp 953/tcp

# Command to run BIND
# -u named: Run as the 'named' user.
# -g named: Run as the 'named' group.
# -f: Stay in foreground, important for Docker logging.
# -c: Specify config file path.
# -m: Enable memory usage debugging (optional, useful for crashes).
CMD ["/usr/sbin/named", "-u", "named", "-f", "-c", "/etc/bind/named.conf"]
