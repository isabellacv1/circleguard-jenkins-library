/**
 * Runs the SonarQube analysis and waits for the quality gate.
 * Disabled by default in circleguardPipeline (sonar: false).
 *
 * Requires the org.sonarqube Gradle plugin in the project and a SonarQube server
 * configured in Jenkins with the given name.
 *
 * Usage: sonarAnalysis(server: 'CircleGuard-SonarQube', projectKey: 'circleguard')
 */
def call(Map params = [:]) {
    String server = params.server ?: 'CircleGuard-SonarQube'
    String projectKey = params.projectKey ?: 'circleguard'

    withSonarQubeEnv(server) {
        gradlew "sonar -Dsonar.projectKey=${projectKey}"
    }
    timeout(time: 10, unit: 'MINUTES') {
        waitForQualityGate abortPipeline: true
    }
}
