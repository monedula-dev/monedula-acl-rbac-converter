# Builds the monedula-acl-rbac CLI into a small image used by the file-based
# examples. The example docker-compose files reference this Dockerfile with the
# repository root as the build context, so the same image (monedula-acl-rbac:examples)
# is built once and reused across every example via Docker's layer cache.
#
# Usage is indirect — each example does:
#   docker compose run --rm converter ./run.sh --check
# which runs the example's own run.sh INSIDE this image, where the CLI is on PATH
# as `monedula-acl-rbac` and bash/diff are available for the golden check.

# --- build stage -------------------------------------------------------------
FROM golang:1.26 AS build
WORKDIR /src

# Module graph first for cache-friendly rebuilds.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/monedula-acl-rbac ./cmd/monedula-acl-rbac

# --- runtime stage -----------------------------------------------------------
FROM debian:stable-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends bash ca-certificates curl diffutils \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/monedula-acl-rbac /usr/local/bin/monedula-acl-rbac

WORKDIR /work
ENTRYPOINT ["bash"]
