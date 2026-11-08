/**
 * Returns the semantic version used to tag the images. Never returns "latest".
 *
 * - If HEAD has a release tag (vX.Y.Z or vX.Y.Z-dev.N, created by semantic-release),
 *   that version is used as is: 1.2.0, 1.3.0-dev.2
 * - Otherwise a pre-release version is built from the last release tag:
 *   1.2.0-build.<BUILD_NUMBER>.<short sha>   (0.0.0-build... if there are no tags yet)
 */
def call() {
    sh 'git fetch --tags --force --quiet || true'

    String exact = sh(
        script: "git describe --tags --exact-match --match 'v[0-9]*' HEAD 2>/dev/null || true",
        returnStdout: true
    ).trim()
    if (exact) {
        return exact.substring(1)
    }

    String last = sh(
        script: "git describe --tags --abbrev=0 --match 'v[0-9]*' HEAD 2>/dev/null || true",
        returnStdout: true
    ).trim()
    String base = last ? last.substring(1).replaceAll(/-.*$/, '') : '0.0.0'
    String sha = sh(script: 'git rev-parse --short=7 HEAD', returnStdout: true).trim()

    return "${base}-build.${env.BUILD_NUMBER}.${sha}"
}
