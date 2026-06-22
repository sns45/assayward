# Multi-stage build for the assayward validating admission webhook.
#
# Stage 1: build — compiles the static binary with CGO disabled so it runs in
#           the distroless/static:nonroot final image without any libc.
# Stage 2: final — minimal distroless image, nonroot user, 8443 exposed.

# ── build stage ─────────────────────────────────────────────────────────────
FROM golang:1.25-alpine AS build

WORKDIR /src

# Copy dependency manifests first to exploit layer caching.
COPY go.mod go.sum ./
RUN go mod download

# Copy the full source tree.
COPY . .

# CGO_ENABLED=0 ensures a fully static binary (no libc dependency).
RUN CGO_ENABLED=0 GOOS=linux go build \
      -trimpath \
      -ldflags="-s -w" \
      -o /assayward-webhook \
      ./surfaces/k8s-webhook/cmd/assayward-webhook

# ── final stage ─────────────────────────────────────────────────────────────
FROM gcr.io/distroless/static:nonroot

# Copy the compiled binary from the build stage.
COPY --from=build /assayward-webhook /assayward-webhook

# Admission webhooks must listen on HTTPS; 8443 is the conventional port.
EXPOSE 8443

# distroless/static:nonroot already sets USER=nonroot (uid 65532).
ENTRYPOINT ["/assayward-webhook"]
