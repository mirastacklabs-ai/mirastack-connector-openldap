# MIRASTACK Connector — OpenLDAP (OSS, AGPL v3)
#
# Build (from monorepo root):
#   docker build -f connectors/AAAA/oss/mirastack-connector-openldap/Dockerfile .
#
# Multi-arch build:
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     -f connectors/AAAA/oss/mirastack-connector-openldap/Dockerfile \
#     -t mirastack-connector-openldap:latest .

FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /src

# Copy the connector SDK (local replace directive dependency).
COPY sdk/ent/connector-sdk/mirastack-connector-sdk-go/ sdk/ent/connector-sdk/mirastack-connector-sdk-go/

# Copy the connector module files first for layer caching.
COPY connectors/AAAA/oss/mirastack-connector-openldap/go.mod \
     connectors/AAAA/oss/mirastack-connector-openldap/go.sum* \
     connectors/AAAA/oss/mirastack-connector-openldap/

WORKDIR /src/connectors/AAAA/oss/mirastack-connector-openldap
RUN go mod download

# Copy the full connector source.
WORKDIR /src
COPY connectors/AAAA/oss/mirastack-connector-openldap/ connectors/AAAA/oss/mirastack-connector-openldap/

WORKDIR /src/connectors/AAAA/oss/mirastack-connector-openldap
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -ldflags "-s -w" -o /mirastack-connector-openldap .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /mirastack-connector-openldap /usr/local/bin/mirastack-connector-openldap

EXPOSE 50051

ENTRYPOINT ["mirastack-connector-openldap"]
