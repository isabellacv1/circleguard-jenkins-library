/**
 * Runs the Playwright end-to-end tests against a DEPLOYED environment.
 *
 * Jenkins has no Node.js, so the tests run inside the official Playwright image
 * through the Docker socket that the controller already mounts. Only the
 * WORKSPACE of this job is mounted, with the same `volume-subpath` pattern as
 * runInContainer (the container must never reach `credentials.xml`, `secrets/`
 * or the workspaces of the other jobs):
 *
 *   --mount type=volume,source=circleguard-jenkins-home,destination=/jh,\
 *          volume-subpath=workspace/<job>
 *
 * Because `/jh` is now the workspace of the job, the working directory is
 * `/jh/tests/e2e-playwright` and the reports are written back through the same
 * mount, so they land in the workspace and can be published with the usual steps.
 *
 * Two guards run before the mount (same as runInContainer): the workspace must
 * live under /var/jenkins_home/workspace (otherwise the subpath would point
 * outside it) and it must already exist (it is created by `Checkout`, which
 * always runs first).
 *
 * Credentials: `e2e-credential` (username/password of a test user of the app).
 *
 * Usage:
 *   runE2E(
 *       baseUrl: 'http://circleguard.example.com',
 *       authBaseUrl: 'http://circleguard.example.com',
 *       gatewayBaseUrl: 'http://circleguard.example.com'
 *   )
 */
def call(Map params = [:]) {
    String baseUrl = params.baseUrl
    String authBaseUrl = params.authBaseUrl ?: baseUrl
    String gatewayBaseUrl = params.gatewayBaseUrl ?: baseUrl
    String credentialsId = params.credentialsId ?: 'e2e-credential'
    String image = params.image ?: 'mcr.microsoft.com/playwright:v1.65.0-noble'
    int timeoutMinutes = params.timeoutMinutes ?: 20
    String volume = params.volume ?: 'circleguard-jenkins-home'

    if (!baseUrl) {
        error 'runE2E: baseUrl is required'
    }
    if (!env.WORKSPACE) {
        error 'runE2E: no workspace available'
    }

    // Only the workspace of this job is mounted: the subpath must live under
    // /var/jenkins_home/workspace (same guard as runInContainer), otherwise the
    // mount would reach secrets/, credentials.xml or another job's workspace.
    String subPath = env.WORKSPACE.replaceFirst('^/var/jenkins_home/', '')
    if (subPath == env.WORKSPACE || !subPath.startsWith('workspace/')) {
        error "runE2E: workspace is not under /var/jenkins_home/workspace: ${env.WORKSPACE}"
    }
    // volume-subpath requires the directory to exist before mounting it, and it
    // is created by the Checkout stage, which always runs first.
    if (!fileExists(env.WORKSPACE)) {
        error "runE2E: workspace ${env.WORKSPACE} does not exist yet (Checkout must run before this step)"
    }

    echo "E2E against ${baseUrl} using ${image}"

    String resultsFile = 'tests/e2e-playwright/results.xml'
    String reportDir = 'tests/e2e-playwright/playwright-report'
    String resultsDir = 'tests/e2e-playwright/test-results'
    Throwable originalFailure = null

    try {
        sh "rm -f ${q(resultsFile)} && rm -rf ${q(reportDir)} ${q(resultsDir)}"
    } catch (Throwable cleanupFailure) {
        throw new RuntimeException("runE2E: could not clean previous E2E evidence: ${cleanupFailure.message}", cleanupFailure)
    }

    // The reports are published even when the tests fail (sh throws on a non-zero exit),
    // so the failure can be analysed from the build: JUnit, HTML report, screenshots,
    // videos and traces. A failure while publishing must never hide the original one.
    try {
        withCredentials([usernamePassword(credentialsId: credentialsId,
                                          usernameVariable: 'E2E_USERNAME',
                                          passwordVariable: 'E2E_PASSWORD')]) {
            timeout(time: timeoutMinutes, unit: 'MINUTES') {
                // The same uid as the workspace owner, so the reports are not
                // written as root and the next checkout can clean them up.
                sh """docker run --rm \
                    --user "\$(id -u):\$(id -g)" \
                    -e HOME=/tmp \
                    --mount 'type=volume,source=${volume},destination=/jh,volume-subpath=${subPath}' \
                    -w /jh/tests/e2e-playwright \
                    -e BASE_URL=${q(baseUrl)} \
                    -e AUTH_BASE_URL=${q(authBaseUrl)} \
                    -e GATEWAY_BASE_URL=${q(gatewayBaseUrl)} \
                    -e E2E_USERNAME \
                    -e E2E_PASSWORD \
                    -e CI=true \
                    ${image} \
                    bash -c 'npm ci && npx playwright test'"""
            }
        }
    } catch (Throwable t) {
        originalFailure = t
    }

    Throwable reportFailure = null
    try {
        if (!fileExists(resultsFile)) {
            error "runE2E: missing ${resultsFile}; the Playwright run produced no results"
        }
        if (!readFile(resultsFile).trim()) {
            error "runE2E: empty ${resultsFile}; the Playwright run produced no results"
        }
        junit testResults: resultsFile, allowEmptyResults: false
        archiveArtifacts artifacts: 'tests/e2e-playwright/playwright-report/**, tests/e2e-playwright/test-results/**',
                         allowEmptyArchive: true
    } catch (Throwable t) {
        reportFailure = t
    }

    if (originalFailure) {
        if (reportFailure) {
            echo "runE2E: report publication also failed: ${reportFailure.message}"
        }
        throw originalFailure
    }
    if (reportFailure) {
        throw reportFailure
    }
}

String q(String value) {
    return "'" + value.replace("'", "'\\''") + "'"
}
