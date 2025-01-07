FROM ubuntu:24.04

RUN apt-get update; apt-get upgrade -y
RUN apt-get install -y git-core \
  build-essential \
  sudo \
  curl \
  just \
  valgrind \
  gcc \
  cmake

WORKDIR /mnt/at_c

CMD [ "tail", "-f", "/dev/null" ]

