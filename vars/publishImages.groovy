/**
 * Builds the Docker images and pushes them to the Nexus docker-hosted registry.
 * Images are tagged only with the semantic version (never "latest").
 *
 * Usage:
 *   publishImages(
 *       registry: 'localhost:8082',
 *       credentialsId: 'nexus-credential',
 *       version: '1.2.0',
 *       images: [[name: 'circleguard/auth-service', dockerfile: 'services/.../Dockerfile', context: '.']]
 *   )
 *
 * Returns the list of pushed image references.
 */
def call(Map params = [:]) {
    String registry = params.registry
    String credentialsId = params.credentialsId ?: 'nexus-credential'
    String version = params.version
    List<Map> images = params.images ?: []

    if (!registry || !version) {
        error 'publishImages: registry and version are required'
    }
    if (version == 'latest') {
        error 'publishImages: images must be tagged with a semantic version, not latest'
    }

    List<String> pushed = []

    // The Dockerfiles use RUN --mount=type=cache, which needs BuildKit (buildx)
    ensureBuildx()

    withCredentials([usernamePassword(credentialsId: credentialsId,
                                      usernameVariable: 'REGISTRY_USER',
                                      passwordVariable: 'REGISTRY_PASS')]) {
        withEnv(["REGISTRY=${registry}"]) {
            sh 'echo "$REGISTRY_PASS" | docker login "$REGISTRY" -u "$REGISTRY_USER" --password-stdin'
            try {
                for (Map image : images) {
                    String ref = "${registry}/${image.name}:${version}"
                    echo "Building ${ref}"
                    sh "docker build -f '${image.dockerfile}' -t '${ref}' '${image.context ?: '.'}'"
                    sh "docker push '${ref}'"
                    // Free disk space on the Jenkins host, the image is already in Nexus
                    sh "docker image rm '${ref}' || true"
                    pushed << ref
                }
            } finally {
                sh 'docker logout "$REGISTRY" || true'
            }
        }
    }

    writeFile file: 'published-images.txt', text: pushed.join('\n') + '\n'
    archiveArtifacts artifacts: 'published-images.txt'
    return pushed
}
