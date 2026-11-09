/**
 * Makes sure the Docker buildx CLI plugin is available, so `docker build` can use BuildKit
 * (the Dockerfiles use RUN --mount=type=cache, which requires it).
 *
 * If buildx is already installed (for example in the Jenkins image) nothing is downloaded.
 * Otherwise a pinned release is downloaded from GitHub, its checksum is verified and it is
 * installed in ~/.docker/cli-plugins. In the Jenkins container that folder lives in
 * jenkins_home, so the download happens only once.
 *
 * Usage: ensureBuildx()  or  ensureBuildx(version: 'v0.19.3')
 */
def call(Map params = [:]) {
    String version = params.version ?: 'v0.19.3'

    withEnv(["BUILDX_VERSION=${version}"]) {
        sh '''#!/bin/bash
            set -euo pipefail
            if docker buildx version >/dev/null 2>&1; then
                echo "buildx available: $(docker buildx version)"
                exit 0
            fi

            case "$(uname -m)" in
                x86_64)  ARCH=amd64 ;;
                aarch64) ARCH=arm64 ;;
                *) echo "Unsupported architecture: $(uname -m)"; exit 1 ;;
            esac

            ASSET="buildx-${BUILDX_VERSION}.linux-${ARCH}"
            BASE_URL="https://github.com/docker/buildx/releases/download/${BUILDX_VERSION}"
            PLUGIN_DIR="${HOME}/.docker/cli-plugins"
            TMP_DIR="$(mktemp -d)"
            trap 'rm -rf "$TMP_DIR"' EXIT

            echo "buildx not found, installing ${ASSET} in ${PLUGIN_DIR}"
            curl -fsSL -o "${TMP_DIR}/${ASSET}" "${BASE_URL}/${ASSET}"
            curl -fsSL -o "${TMP_DIR}/checksums.txt" "${BASE_URL}/checksums.txt"
            (cd "$TMP_DIR" && grep " \\*${ASSET}$" checksums.txt | sed 's/ \\*/  /' | sha256sum -c -)

            mkdir -p "$PLUGIN_DIR"
            install -m 0755 "${TMP_DIR}/${ASSET}" "${PLUGIN_DIR}/docker-buildx"
            docker buildx version
        '''
    }
}
