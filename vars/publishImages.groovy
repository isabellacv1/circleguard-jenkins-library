/**
 * Builds the Docker images and pushes them to the Nexus docker-hosted registry.
 * Images are tagged only with the semantic version (never "latest").
 *
 * Optional vulnerability scan (opt-in, default OFF): when `scanVulnerabilities`
 * is enabled, every image is scanned with Trivy BETWEEN `docker build` and
 * `docker push`, so a HIGH/CRITICAL finding never reaches the registry. The scan
 * needs no credentials and no extra service: it reads the image from the local
 * Docker daemon through the socket (see trivyImageScan). A failure aborts the
 * publication of that image; the images already pushed stay in the registry
 * (partial publication is accepted, the version is unique to this build).
 *
 * Usage:
 *   publishImages(
 *       registry: 'localhost:8082',
 *       credentialsId: 'nexus-credential',
 *       version: '1.2.0',
 *       images: [[name: 'circleguard/auth-service', dockerfile: 'services/.../Dockerfile', context: '.']]
 *   )
 *
 *   publishImages(..., scanVulnerabilities: true, scanBranches: ['dev'])
 *
 * Returns the list of pushed image references.
 */
def call(Map params = [:]) {
    String registry = params.registry
    String credentialsId = params.credentialsId ?: 'nexus-credential'
    String version = params.version
    List<Map> images = params.images ?: []

    // Trivy Image (opt-in: every default keeps the previous behaviour).
    boolean scanVulnerabilities = params.scanVulnerabilities ?: false
    String trivyToolImage = params.trivyToolImage ?: 'aquasec/trivy:0.76.2'
    String scanSeverity = params.scanSeverity ?: 'HIGH,CRITICAL'
    int scanTimeout = params.scanTimeout ?: 15
    List<String> scanBranches = params.scanBranches ?: ['dev', 'main']
    String scanIgnoreFile = params.scanIgnoreFile ?: '.trivyignore.yaml'

    if (!registry || !version) {
        error 'publishImages: registry and version are required'
    }
    if (version == 'latest') {
        error 'publishImages: images must be tagged with a semantic version, not latest'
    }

    List<String> pushed = []

    // The Dockerfiles use RUN --mount=type=cache, which needs BuildKit (buildx)
    ensureBuildx()
    // Make room before building: the Jenkins host disk is small
    dockerCleanup()

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
                    // Scan the LOCAL image between `docker build` and `docker push`: a
                    // HIGH/CRITICAL finding must never reach the registry. Both gates are
                    // required: the opt-in flag AND a known branch listed in scanBranches;
                    // without a BRANCH_NAME (or with an unlisted one) the scan is skipped.
                    // PRs never reach this stage: it is gated by `publishBranches`.
                    if (scanVulnerabilities && env.BRANCH_NAME &&
                        scanBranches.contains(env.BRANCH_NAME)) {
                        echo "Trivy image scan: ${ref}"
                        trivyImageScan(ref: ref,
                                       toolImage: trivyToolImage,
                                       severity: scanSeverity,
                                       timeout: scanTimeout,
                                       ignoreFile: scanIgnoreFile)
                    }
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
