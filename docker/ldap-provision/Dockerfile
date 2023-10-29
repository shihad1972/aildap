FROM debian:bookworm

USER root
COPY libailsa_0.1-2_amd64.deb .

RUN apt-get update -y
RUN apt-get install -y build-essential autoconf automake git libtool
RUN apt-get install -y libglib2.0-dev libssl-dev libldap2-dev check
RUN dpkg -i libailsa_0.1-2_amd64.deb
