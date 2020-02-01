FROM ubuntu:18.04

RUN apt-get update && apt-get install -y sudo

ARG fuzzer_name
ARG target_name
# magma_root is relative to the docker-build's working directory
# The Docker image must be built in the root of the magma directory
ARG magma_root=./

# Path variables inside the container
ENV MAGMA_R /magma
ENV MAGMA 	${MAGMA_R}/magma
ENV OUT		/magma_out
ENV SHARED 	/magma_shared
ENV FUZZER 	${MAGMA_R}/fuzzers/${fuzzer_name}
ENV TARGET 	${MAGMA_R}/targets/${target_name}

RUN groupadd -r magma && useradd -K UMASK=0000 -r -g magma magma
RUN	echo "magma:amgam" | chpasswd && usermod -a -G sudo magma
COPY --chown=magma:magma ${magma_root} ${MAGMA_R}
RUN mkdir -p ${SHARED} ${OUT} && \
	chown magma:magma ${SHARED} ${OUT} && \
	chmod 744 ${SHARED} ${OUT}

RUN ${MAGMA}/preinstall.sh
RUN ${FUZZER}/preinstall.sh
RUN ${TARGET}/preinstall.sh

USER magma:magma

ENV CC	gcc
ENV CXX g++

RUN ${MAGMA}/prebuild.sh
RUN ${FUZZER}/fetch.sh && ${FUZZER}/build.sh
RUN ${TARGET}/fetch.sh && ${MAGMA}/apply_patches.sh

ENV CFLAGS -include "${MAGMA}/src/canary.h -DMAGMA_ENABLE_CANARIES -DMAGMA_FATAL_CANARIES" -g -O0
ENV CXXFLAGS -include "${MAGMA}/src/canary.h -DMAGMA_ENABLE_CANARIES -DMAGMA_FATAL_CANARIES" -g -O0
ENV LIBS -l:canary.o -lrt
ENV LDFLAGS -L"${OUT}" -g

RUN ${FUZZER}/instrument.sh

ENTRYPOINT "${MAGMA}/run.sh"
