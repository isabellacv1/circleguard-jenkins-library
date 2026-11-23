/**
 * Runs the SonarQube analysis and waits for the quality gate.
 * Disabled by default in circleguardPipeline (sonar: false).
 *
 * Requires the org.sonarqube Gradle plugin in the project, a SonarQube server configured
 * in Jenkins with the given name, and a SonarQube webhook pointing to <jenkins>/sonarqube-webhook/
 * so waitForQualityGate gets the result.
 *
 * Usage: sonarAnalysis(server: 'CircleGuard-SonarQube', projectKey: 'CircleGuard')
 */
def call(Map params = [:]) {
    String server = params.server ?: 'CircleGuard-SonarQube'
    String projectKey = params.projectKey ?: 'circleguard'

    withSonarQubeEnv(server) {
        withEnv(["SONAR_PROJECT_KEY=${projectKey}"]) {
            sh 'chmod +x gradlew'
            // SONAR_HOST_URL and SONAR_AUTH_TOKEN are provided by withSonarQubeEnv
            sh '''./gradlew sonar --console=plain \
                -Dsonar.projectKey="$SONAR_PROJECT_KEY" \
                -Dsonar.host.url="$SONAR_HOST_URL" \
                -Dsonar.token="$SONAR_AUTH_TOKEN"'''
        }
    }
    // The gate result is PERSISTED so the consolidated coverage & quality report
    // (qualityReport) can show it. abortPipeline: true would throw before the
    // file could be written, so the gate is fetched without aborting and the
    // build is failed here instead: the blocking behaviour is identical and the
    // evidence survives it.
    Map gate = [:]
    timeout(time: 10, unit: 'MINUTES') {
        gate = waitForQualityGate abortPipeline: false
    }
    String status = (gate?.status ?: 'UNKNOWN').toString()
    writeFile file: 'sonar-quality-gate.txt',
              text: "status=${status}\nproject=${projectKey}\nserver=${server}\n"
    if (status != 'OK') {
        error "sonarAnalysis: SonarQube quality gate ${status} for project " +
              "${projectKey}: the build is blocked until the gate passes"
    }
    echo "sonarAnalysis: quality gate OK for ${projectKey}"
}
