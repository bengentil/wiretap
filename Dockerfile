FROM ubuntu:22.04 as build-ubuntu
RUN apt-get update && \
    apt-get install -y ca-certificates make golang clang llvm libbpf-dev bear linux-tools-generic

FROM fedora:36 as build-fedora
RUN dnf -y update && \
    dnf install -y make golang clang libbpf-devel bear bpftool musl-devel && \
    dnf -y clean all

FROM build-fedora as build-src
COPY . /src
WORKDIR /src
RUN make all

FROM scratch
COPY --from=build-src /src/wiretap /usr/bin/wiretap
ENTRYPOINT ["/usr/bin/wiretap"]

