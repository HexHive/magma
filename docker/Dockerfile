FROM ubuntu:18.04

# TODO remove sudo for user "magma" to avoid unwanted priv escalation from
# other attack vectors.

RUN apt-get update && apt-get install -y sudo

ARG fuzzer_name
ARG target_name
ARG USER_ID=1000
ARG GROUP_ID=1000
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

RUN mkdir -p /home && \
	groupadd -g ${GROUP_ID} magma && \
	useradd -l -u ${USER_ID} -K UMASK=0000 -d /home -g magma magma && \
	chown magma:magma /home
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
