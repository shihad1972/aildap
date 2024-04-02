FROM debian:bookworm

USER root

RUN apt-get update -y && apt-get install -y wget
COPY ailsatech.list /etc/apt/sources.list.d/ailsatech.list
RUN wget -O - http://debian.shihad.org/debian/ailsatech.gpg  | tee /etc/apt/trusted.gpg.d/ailsatech.asc
RUN apt-get update -y && apt-get install -y build-essential autoconf automake pkg-config git libtool libgcrypt20-dev libssl-dev libldap2-dev check libkrb5-dev libailsa-dev
