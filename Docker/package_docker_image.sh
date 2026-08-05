#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE_NAME="${IMAGE_NAME:-check-point-hardening-app-se}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
DOCKER_PLATFORM="${DOCKER_PLATFORM:-linux/amd64}"
OUTPUT_DIR="${OUTPUT_DIR:-${ROOT_DIR}/dist}"
ARCHIVE_PATH="${OUTPUT_DIR}/${IMAGE_NAME}-${IMAGE_TAG}-${DOCKER_PLATFORM//\//-}.tar.gz"

command -v docker >/dev/null 2>&1 || {
  echo "Docker is required but was not found in PATH." >&2
  exit 1
}

mkdir -p "${OUTPUT_DIR}"

echo "Building ${IMAGE_NAME}:${IMAGE_TAG} for ${DOCKER_PLATFORM}..."
docker build \
  --platform "${DOCKER_PLATFORM}" \
  --tag "${IMAGE_NAME}:${IMAGE_TAG}" \
  --file "${ROOT_DIR}/Docker/Dockerfile" \
  "${ROOT_DIR}"

echo "Saving ${ARCHIVE_PATH}..."
docker save "${IMAGE_NAME}:${IMAGE_TAG}" | gzip -9 > "${ARCHIVE_PATH}"

cat <<EOF

Docker image bundle created:
  ${ARCHIVE_PATH}

On the receiving machine:
  gunzip -c "$(basename "${ARCHIVE_PATH}")" | docker load
  docker run -d --name check-point-hardening-app-se --init --restart unless-stopped --shm-size=1g -p 3100:3100 ${IMAGE_NAME}:${IMAGE_TAG}

Open:
  http://127.0.0.1:3100
EOF
