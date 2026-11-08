package org.circleguard.ci

/**
 * Parameters accepted by circleguardPipeline().
 * Every value has a default, so the Jenkinsfile only sets what changes.
 */
class PipelineConfig implements Serializable {
    boolean integrationTests = true
    boolean sonar = false
    String sonarServer = 'CircleGuard-SonarQube'
    String sonarProjectKey = 'circleguard'
    int buildTimeout = 30
    int testTimeout = 45
    int integrationTimeout = 30
    int buildsToKeep = 20

    PipelineConfig(Map config) {
        Map c = config ?: [:]
        this.integrationTests = c.integrationTests != null ? c.integrationTests as boolean : this.integrationTests
        this.sonar = c.sonar != null ? c.sonar as boolean : this.sonar
        this.sonarServer = c.sonarServer ?: this.sonarServer
        this.sonarProjectKey = c.sonarProjectKey ?: this.sonarProjectKey
        this.buildTimeout = c.buildTimeout ? c.buildTimeout as int : this.buildTimeout
        this.testTimeout = c.testTimeout ? c.testTimeout as int : this.testTimeout
        this.integrationTimeout = c.integrationTimeout ? c.integrationTimeout as int : this.integrationTimeout
        this.buildsToKeep = c.buildsToKeep ? c.buildsToKeep as int : this.buildsToKeep
    }
}
