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

    boolean publish = false
    String registry = 'localhost:8082'
    String registryCredentialsId = 'nexus-credential'
    List<String> publishBranches = ['dev', 'main']
    List<Map> images = [
        [name: 'circleguard/auth-service',      dockerfile: 'services/circleguard-auth-service/Dockerfile',      context: '.'],
        [name: 'circleguard/identity-service',  dockerfile: 'services/circleguard-identity-service/Dockerfile',  context: '.'],
        [name: 'circleguard/promotion-service', dockerfile: 'services/circleguard-promotion-service/Dockerfile', context: '.'],
        [name: 'circleguard/form-service',      dockerfile: 'services/circleguard-form-service/Dockerfile',      context: '.'],
        [name: 'circleguard/gateway-service',   dockerfile: 'services/circleguard-gateway-service/Dockerfile',   context: '.'],
        [name: 'circleguard/web',               dockerfile: 'mobile/Dockerfile',                                 context: 'mobile'],
    ]

    int buildTimeout = 30
    int testTimeout = 45
    int integrationTimeout = 30
    int publishTimeout = 40
    int buildsToKeep = 20

    PipelineConfig(Map config) {
        Map c = config ?: [:]
        this.integrationTests = c.integrationTests != null ? c.integrationTests as boolean : this.integrationTests
        this.sonar = c.sonar != null ? c.sonar as boolean : this.sonar
        this.sonarServer = c.sonarServer ?: this.sonarServer
        this.sonarProjectKey = c.sonarProjectKey ?: this.sonarProjectKey
        this.publish = c.publish != null ? c.publish as boolean : this.publish
        this.registry = c.registry ?: this.registry
        this.registryCredentialsId = c.registryCredentialsId ?: this.registryCredentialsId
        this.publishBranches = c.publishBranches ?: this.publishBranches
        this.images = c.images ?: this.images
        this.buildTimeout = c.buildTimeout ? c.buildTimeout as int : this.buildTimeout
        this.testTimeout = c.testTimeout ? c.testTimeout as int : this.testTimeout
        this.integrationTimeout = c.integrationTimeout ? c.integrationTimeout as int : this.integrationTimeout
        this.publishTimeout = c.publishTimeout ? c.publishTimeout as int : this.publishTimeout
        this.buildsToKeep = c.buildsToKeep ? c.buildsToKeep as int : this.buildsToKeep
    }
}
