ARG ARCH="amd64"
ARG OS="linux"
FROM quay.io/prometheus/busybox-${OS}-${ARCH}:glibc
ARG ARCH="amd64"
ARG OS="linux"
COPY .build/${OS}-${ARCH}/ssh_exporter /ssh_exporter
EXPOSE 9312
ENTRYPOINT ["/ssh_exporter"]
