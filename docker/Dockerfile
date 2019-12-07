FROM ubuntu:18.04

ENV WORKDIR /root
WORKDIR ${WORKDIR}

###### Dependencies ######
RUN apt update
RUN apt install -y git make build-essential cmake autoconf automake \
    libtool pkgconf \
    zlib1g-dev liblzma-dev libfreetype6-dev libfontconfig1-dev \
    libjpeg-dev libopenjp2-7-dev python-dev \
    libunwind-dev binutils-dev curl python3 python3-pip clang-7 wget screen
RUN update-alternatives --install /usr/bin/python python /usr/bin/python2 0
RUN update-alternatives --install /usr/bin/python python /usr/bin/python3 1
##########################

RUN mkdir fuzzers

###### AFL ######

RUN git clone --depth 1 https://github.com/google/AFL.git fuzzers/afl
RUN cd fuzzers/afl && make -j

#################

###### AFLFast ######

RUN git clone --depth 1 https://github.com/mboehme/aflfast.git fuzzers/aflfast
RUN cd fuzzers/aflfast && make -j

#####################

###### MOpt-AFL ######

RUN git clone --depth 1 https://github.com/puppet-meteor/MOpt-AFL.git fuzzers/moptafl
RUN cd fuzzers/moptafl && mv "MOpt-AFL V1.0" fuzzer
RUN cd fuzzers/moptafl/fuzzer && make -j

######################

###### FairFuzz ######

RUN git clone --depth 1 https://github.com/carolemieux/afl-rb.git fuzzers/fairfuzz
RUN cd fuzzers/fairfuzz && make -j

######################

###### honggfuzz ######

RUN git clone --depth 1 https://github.com/google/honggfuzz.git fuzzers/honggfuzz
RUN cd fuzzers/honggfuzz && make -j

#######################

###### Angora ######

RUN git clone --depth 1 https://github.com/AngoraFuzzer/Angora.git fuzzers/angora
# RUN curl --output - -L https://github.com/llvm/llvm-project/releases/download/llvmorg-7.1.0/llvm-7.1.0.src.tar.xz | xzcat | tar xvf -
# RUN cd llvm-7.1.0.src/ && mkdir build && cd build/ && cmake .. && make -j && make install

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --profile minimal -y
# ENV PREFIX ${WORKDIR}
ENV PATH "/root/.cargo/bin:${PATH}"
RUN cd fuzzers/angora && build/build.sh

ENV PATH "/root/clang+llvm/bin:${PATH}"
ENV LD_LIBRARY_PATH="/root/clang+llvm/lib:${LD_LIBRARY_PATH}"

####################

###### Magma ######

RUN git clone --depth 1 --recurse-submodules https://github.com/HexHive/magma.git
RUN pip3 install -r magma/tools/requirements.txt
RUN mkdir /root/campaigns
RUN mkdir /root/postproc

###################
