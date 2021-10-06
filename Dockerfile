FROM golang AS build-env-golang
ENV CGO_ENABLED=0
WORKDIR /go/src/github.com/okzk/oidc-radius
ADD *.go go.* ./
RUN go install


FROM alpine

RUN apk add --no-cache ca-certificates
COPY --from=build-env-golang /go/bin/oidc-radius /usr/local/bin/

ENV RADIUS_SECRET= \
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

EXPOSE 1812/udp 1813/udp

CMD ["/usr/local/bin/oidc-radius"]
