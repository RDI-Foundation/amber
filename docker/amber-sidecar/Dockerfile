# syntax=docker/dockerfile:1.12

FROM alpine:3.20

RUN --mount=type=cache,target=/var/cache/apk,sharing=locked \
    apk add --update-cache iptables ip6tables iproute2 libc-utils socat
