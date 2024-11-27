FROM golang:1.22 AS build-env-golang
ENV CGO_ENABLED=0
WORKDIR /go/github.com/ca-ciu/oidc-radius
ADD . ./
RUN go install

FROM alpine

RUN apk update \
        && apk upgrade \
        && apk add --no-cache \
        ca-certificates \
        && update-ca-certificates 2>/dev/null || true

COPY --from=build-env-golang /go/bin/oidc-radius /usr/local/bin/

ENV RADIUS_SECRET= \
    RADIUS_TLS_CERT=/etc/radius/cert.pem \
    RADIUS_TLS_KEY=/etc/radius/key.pem \
    RADIUS_TLS_PORT=2083 \
    RADIUS_ACCOUNT_PORT=1813 \
    RADIUS_REQUEST_PORT=1812 \
    CIBA_ISSUER= \
    CIBA_AUTHN_ENDPOINT= \
    CIBA_TOKEN_ENDPOINT= \
    CIBA_SCOPE=openid \
    CIBA_CLIENT_ID= \
    CIBA_CLIENT_SECRET= \
    REDIS_HOST= \
    REDIS_PORT=6379 \
    REDIS_PASSWORD= \
    CACHE_EXPIRATION_SEC=10800 \
    USERNAME_SEPARATOR=

EXPOSE 1812/udp 1813/udp 2083/tcp

CMD ["/usr/local/bin/oidc-radius"]
