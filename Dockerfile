FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/uploader . \
 && mkdir -p /out/data /out/spool

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.source="https://github.com/MattJackson/uploader" \
      org.opencontainers.image.description="Self-hosted drop box: anyone with the link uploads, only you see the files" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /out/uploader /uploader
# Owned by the nonroot user so fresh named volumes are writable.
COPY --from=build --chown=65532:65532 /out/data /data
COPY --from=build --chown=65532:65532 /out/spool /spool
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD ["/uploader", "healthcheck"]
ENTRYPOINT ["/uploader"]
