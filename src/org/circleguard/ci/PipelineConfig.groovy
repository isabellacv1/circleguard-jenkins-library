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

    // Deployment to AWS (HU-13). The environment files live in deploy/environments/.
    boolean deploy = false
    String environment = 'dev'
    List<String> deployBranches = ['dev']
    String deployCredentialId = null     // defaults to "${environment}-credential"
    int deployTimeout = 20
    int verifyTimeout = 15
    int healthRetries = 20
    int healthIntervalSeconds = 10
    // Components of "Parte 1" and how to check that they are available.
    List<Map> services = [
        [name: 'gateway',   port: 8087],
        [name: 'auth',      port: 8180],
        [name: 'identity',  port: 8083],
        [name: 'form',      port: 8086],
        [name: 'promotion', port: 8088],
        [name: 'web',       port: 8081, path: '/'],
    ]

    // Post-deployment smoke tests (HU-15).
    boolean smokeTests = true
    String smokeCredentialsId = 'e2e-credential'  // user for the login check (null skips it)
    int smokeTimeout = 10

    // Version promotion between environments (HU-14).
    boolean e2e = true                       // Playwright tests against the deployed dev
    int e2eTimeout = 20
    String e2eCredentialsId = 'e2e-credentials'
    String e2eImage = 'mcr.microsoft/playwright:v1.65.0'
    boolean promote = false                  // dev -> stage -> prod
    boolean stageApproval = false            // stage is promoted automatically after E2E
    boolean prodApproval = true              // prod always waits for a manual input
    int approvalTimeout = 240                // minutes the approver has to answer
    String promotionRecordFile = 'promotion-record.txt'

    int buildTimeout = 30
    int testTimeout = 45
    int integrationTimeout = 30
    int publishTimeout = 40
    int buildsToKeep = 20

    String discordCredentialsId = 'discord-webhook-url'

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
        this.deploy = c.deploy != null ? c.deploy as boolean : this.deploy
        this.environment = c.environment ?: this.environment
        this.deployBranches = c.deployBranches ?: this.deployBranches
        this.deployCredentialId = c.deployCredentialId ?: this.deployCredentialId
        this.deployTimeout = c.deployTimeout ? c.deployTimeout as int : this.deployTimeout
        this.verifyTimeout = c.verifyTimeout ? c.verifyTimeout as int : this.verifyTimeout
        this.healthRetries = c.healthRetries ? c.healthRetries as int : this.healthRetries
        this.healthIntervalSeconds = c.healthIntervalSeconds ? c.healthIntervalSeconds as int : this.healthIntervalSeconds
        this.services = c.services ?: this.services
        this.smokeTests = c.smokeTests != null ? c.smokeTests as boolean : this.smokeTests
        this.smokeCredentialsId = c.containsKey('smokeCredentialsId') ? c.smokeCredentialsId : this.smokeCredentialsId
        this.smokeTimeout = c.smokeTimeout ? c.smokeTimeout as int : this.smokeTimeout
        this.e2e = c.e2e != null ? c.e2e as boolean : this.e2e
        this.e2eTimeout = c.e2eTimeout ? c.e2eTimeout as int : this.e2eTimeout
        this.e2eCredentialsId = c.e2eCredentialsId ?: this.e2eCredentialsId
        this.e2eImage = c.e2eImage ?: this.e2eImage
        this.promote = c.promote != null ? c.promote as boolean : this.promote
        this.stageApproval = c.stageApproval != null ? c.stageApproval as boolean : this.stageApproval
        this.prodApproval = c.prodApproval != null ? c.prodApproval as boolean : this.prodApproval
        this.approvalTimeout = c.approvalTimeout ? c.approvalTimeout as int : this.approvalTimeout
        this.promotionRecordFile = c.promotionRecordFile ?: this.promotionRecordFile
        this.buildTimeout = c.buildTimeout ? c.buildTimeout as int : this.buildTimeout
        this.testTimeout = c.testTimeout ? c.testTimeout as int : this.testTimeout
        this.integrationTimeout = c.integrationTimeout ? c.integrationTimeout as int : this.integrationTimeout
        this.publishTimeout = c.publishTimeout ? c.publishTimeout as int : this.publishTimeout
        this.buildsToKeep = c.buildsToKeep ? c.buildsToKeep as int : this.buildsToKeep
        this.discordCredentialsId = c.discordCredentialsId != null ? c.discordCredentialsId : this.discordCredentialsId
    }
}
