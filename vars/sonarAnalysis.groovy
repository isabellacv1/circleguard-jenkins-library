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
    timeout(time: 10, unit: 'MINUTES') {
        waitForQualityGate abortPipeline: true
    }
}
