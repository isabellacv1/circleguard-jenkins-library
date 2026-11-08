/**
 * Publishes the JUnit results and archives the test and JaCoCo reports of every service.
 * Meant to run in post { always { } } so the evidence is kept even when a stage fails.
 */
def call() {
    junit allowEmptyResults: true,
          testResults: 'services/*/build/test-results/test/*.xml, services/*/build/test-results/integrationTest/*.xml'
    archiveArtifacts allowEmptyArchive: true,
                     artifacts: 'services/*/build/reports/tests/**, services/*/build/reports/jacoco/**'
}
