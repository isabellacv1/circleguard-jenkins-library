/**
 * Runs the Playwright end-to-end tests against a DEPLOYED environment.
 *
 * Jenkins has no Node.js, so the tests run inside the official Playwright image
 * through the Docker socket that the controller already mounts. The Jenkins
 * workspace is reached from the Docker daemon through the named volume
 * (`circleguard-jenkins-home` -> /var/jenkins_home), which is why the path is
 * translated before mounting it.
 *
 * The reports (JUnit XML and the HTML report) are written back into the
 * workspace through the volume, so they can be published with the usual steps.
 *
 * Credentials: `e2e-credential` (username/password of a test user of the app).
 *
 * Usage:
 *   runE2E(
 *       baseUrl: 'http://44.212.47.173:8081',
 *       authBaseUrl: 'http://44.212.47.173:8180',
 *       gatewayBaseUrl: 'http://44.212.47.173:8087'
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

    // /var/jenkins_home/workspace/xxx  ->  /jh/workspace/xxx (inside the volume)
    String hostWorkspace = env.WORKSPACE.replaceFirst('^/var/jenkins_home', '/jh')

    echo "E2E against ${baseUrl} using ${image}"

    withCredentials([usernamePassword(credentialsId: credentialsId,
                                      usernameVariable: 'E2E_USERNAME',
                                      passwordVariable: 'E2E_PASSWORD')]) {
        timeout(time: timeoutMinutes, unit: 'MINUTES') {
            // The same uid as the workspace owner, so the reports are not
            // written as root and the next checkout can clean them up.
            sh """docker run --rm \
                --user "\$(id -u):\$(id -g)" \
                -e HOME=/tmp \
                -v ${volume}:/jh \
                -w ${hostWorkspace}/tests/e2e-playwright \
                -e BASE_URL='${baseUrl}' \
                -e AUTH_BASE_URL='${authBaseUrl}' \
                -e GATEWAY_BASE_URL='${gatewayBaseUrl}' \
                -e E2E_USERNAME \
                -e E2E_PASSWORD \
                -e CI=true \
                ${image} \
                bash -c 'npm ci && npx playwright test'"""
        }
    }

    junit testResults: 'tests/e2e-playwright/results.xml', allowEmptyResults: false
    archiveArtifacts artifacts: 'tests/e2e-playwright/playwright-report/**', allowEmptyArchive: true
}
