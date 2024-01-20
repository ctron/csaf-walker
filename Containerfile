FROM --platform=$BUILDPLATFORM registry.access.redhat.com/ubi9/ubi-minimal:latest AS collect

RUN mkdir /download
COPY download/* /download/
WORKDIR /download
RUN \
    find && \
    mkdir -p linux/aarch64 && \
    mkdir -p linux/amd64 && \
    mv csaf-aarch64-unknown-linux-gnu/csaf-aarch64-unknown-linux-gnu linux/aarch64/csaf && \
    mv sbom-aarch64-unknown-linux-gnu/sbom-aarch64-unknown-linux-gnu linux/aarch64/sbom && \
    mv csaf-x86_64-unknown-linux-gnu/csaf-x86_64-unknown-linux-gnu linux/amd64/csaf && \
    mv sbom-x86_64-unknown-linux-gnu/sbom-x86_64-unknown-linux-gnu linux/amd64/sbom

FROM registry.access.redhat.com/ubi9/ubi-minimal:latest

LABEL org.opencontainers.image.source="https://github.com/ctron/csaf-walker"

ARG TARGETPLATFORM

#RUN microdnf update -y && microdnf install -y jq

RUN echo ${TARGETPLATFORM}

COPY --from=collect /download/${TARGETPLATFORM}/csaf /usr/local/bin/
COPY --from=collect /download/${TARGETPLATFORM}/sbom /usr/local/bin/

RUN \
    chmod a+x /usr/local/bin/csaf && \
    chmod a+x /usr/local/bin/sbom
