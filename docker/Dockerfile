# Builder for the tcw toolchains: Debian 10 (glibc 2.28) + crosstool-NG.
# Everything is pinned so the build environment is traceable and reproducible.
ARG BASE_IMAGE=debian:10@sha256:2a0c1b9175adf759420fe0fbd7f5b449038319171eb76554bb76cbe172b62b42
FROM ${BASE_IMAGE}
ARG BASE_IMAGE
ARG CTNG_VERSION=1.29.0
ARG CTNG_SHA512=04cd24c8ec60d250f4d73bf41e04131a142169cd89a26d49c9725419e248834d455fb9fb5c38c132f314dd5e34687eefb63f7a104f22764bd44ec2b06982acee
ARG CTNG_URL=https://github.com/crosstool-ng/crosstool-ng/releases/download/crosstool-ng-${CTNG_VERSION}/crosstool-ng-${CTNG_VERSION}.tar.xz

ENV DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8 LC_ALL=C.UTF-8

# Debian 10 is EOL: use the frozen archive.
COPY packages.lock /etc/tcw/packages.lock
RUN printf '%s\n' \
      'deb http://archive.debian.org/debian buster main' \
      'deb http://archive.debian.org/debian-security buster/updates main' \
      > /etc/apt/sources.list \
 && echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99archive \
 && apt-get update \
 && apt-get install -y --no-install-recommends $(cat /etc/tcw/packages.lock) \
 && rm -rf /var/lib/apt/lists/*

# crosstool-NG, verified against a pinned SHA-512. The source tarball is kept for compliance.
# ctng-build-deps.lock (ncurses headers for ct-ng's kconfig) is installed only for this step,
# recorded, and purged again: if left installed, gdb's configure would link the host's
# libncursesw instead of crosstool-NG's static ncurses.
COPY ctng-build-deps.lock /etc/tcw/ctng-build-deps.lock
RUN apt-get update \
 && apt-get install -y --no-install-recommends $(cat /etc/tcw/ctng-build-deps.lock) \
 && dpkg-query -W -f '${db:Status-Status}\t${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n' \
      $(sed 's/=.*//' /etc/tcw/ctng-build-deps.lock) > /etc/tcw/ctng-build-deps.dpkg \
 && mkdir -p /opt/ctng/src /tmp/ctng && cd /tmp/ctng \
 && curl -fsSL -o /opt/ctng/src/crosstool-ng-${CTNG_VERSION}.tar.xz "${CTNG_URL}" \
 && echo "${CTNG_SHA512}  /opt/ctng/src/crosstool-ng-${CTNG_VERSION}.tar.xz" | sha512sum -c - \
 && tar xf /opt/ctng/src/crosstool-ng-${CTNG_VERSION}.tar.xz --strip-components=1 \
 && ./configure --prefix=/opt/ctng \
 && make -j"$(nproc)" && make install \
 && cd / && rm -rf /tmp/ctng \
 && apt-get purge -y $(sed 's/=.*//' /etc/tcw/ctng-build-deps.lock) \
 && rm -rf /var/lib/apt/lists/*
ENV PATH=/opt/ctng/bin:${PATH}

# Provenance record consumed by the SBOM generator.
RUN printf '{\n  "base_image": "%s",\n  "ctng_version": "%s",\n  "ctng_url": "%s",\n  "ctng_sha512": "%s"\n}\n' \
      "${BASE_IMAGE}" "${CTNG_VERSION}" "${CTNG_URL}" "${CTNG_SHA512}" > /etc/tcw/build-info.json

# ct-ng refuses to run as root.
RUN useradd -m -u 1000 builder
USER builder
WORKDIR /work
