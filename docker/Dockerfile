FROM ubuntu:18.04

ENV WORKDIR /root
WORKDIR ${WORKDIR}

###### Dependencies ######
RUN apt update
RUN apt install -y git make build-essential cmake autoconf automake \
    libtool pkgconf \
    zlib1g-dev liblzma-dev libfreetype6-dev libfontconfig1-dev \
    libjpeg-dev libopenjp2-7-dev python-dev \
    libunwind-dev binutils-dev curl python3 python3-pip clang-7 wget screen \
    gawk ninja-build texinfo bison
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

###### AFLGo ######

RUN git clone --depth 1 https://github.com/aflgo/aflgo fuzzers/aflgo
RUN pip3 install networkx pydot pydotplus

# Download commit-analysis tool
RUN cd fuzzers/aflgo && \
    wget https://raw.githubusercontent.com/jay/showlinenum/develop/showlinenum.awk && \
    chmod +x showlinenum.awk

# AFLGo requires gold linker
RUN git clone --depth 1 git://sourceware.org/git/binutils-gdb.git binutils
RUN mkdir binutils/build
RUN cd binutils/build && \
    ../configure --enable-gold --enable-plugins --disable-werror && \
    make -j all-gold && \
    make install || true

# Build LLVM with gold linker
RUN curl --output - -L https://github.com/llvm/llvm-project/releases/download/llvmorg-7.1.0/llvm-7.1.0.src.tar.xz | xzcat | tar xvf -
RUN cd llvm-7.1.0.src/ && mkdir build && cd build && \
    cmake .. -DLLVM_BINUTILS_INCDIR=/usr/local/include \
        -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
        -DCMAKE_BUILD_TYPE=Release -DLLVM_TARGETS_TO_BUILD="X86" \
        -DLLVM_BUILD_EXAMPLES=Off -DLLVM_INCLUDE_EXAMPLES=Off \
        -DLLVM_BUILD_TESTS=Off -DLLVM_INCLUDE_TESTS=Off -G Ninja
RUN cd llvm-7.1.0.src/build && cmake --build .
RUN cd llvm-7.1.0.src/build && \
    cmake -DCMAKE_INSTALL_PREFIX=/root/clang+llvm -P cmake_install.cmake --target install
RUN mkdir /root/clang+llvm/lib/bfd-plugins
RUN ln -s /root/clang+llvm/lib/libLTO.so /usr/lib/bfd-plugins
RUN ln -s /root/clang+llvm/lib/LLVMgold.so /usr/lib/bfd-plugins
RUN rm -rf llvm-7.1.0.src

# Build AFLGo
RUN make -C fuzzers/aflgo clean all && make -C fuzzers/aflgo/llvm_mode clean all

###################

###### Magma ######

RUN git clone --depth 1 --recurse-submodules https://github.com/HexHive/magma.git
RUN pip3 install -r magma/tools/requirements.txt
RUN mkdir /root/campaigns
RUN mkdir /root/postproc

###################
