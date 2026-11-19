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

    // Frees Docker disk space on the Jenkins host after every build.
    boolean dockerCleanup = true

    // Post-deployment smoke tests (HU-15).
    boolean smokeTests = true
    String smokeCredentialsId = 'e2e-credential'  // user for the login check (null skips it)
    int smokeTimeout = 10

    // Version promotion between environments (HU-14).
    boolean e2e = true                       // Playwright tests against the deployed dev
    int e2eTimeout = 20
    String e2eCredentialsId = 'e2e-credential'
    String e2eImage = 'mcr.microsoft.com/playwright:v1.65.0-noble'
    boolean promote = false                  // dev -> stage -> prod
    boolean stageApproval = false            // stage is promoted automatically after E2E
    boolean prodApproval = true              // prod always waits for a manual input
    int approvalTimeout = 240                // minutes the approver has to answer
    String promotionRecordFile = 'promotion-record.txt'

    // Static validation of the infrastructure as code (Terraform + Trivy).
    // Off by default: enabling it pulls the pinned images on the first build.
    // Neither step needs AWS credentials, and none of them runs plan/apply.
    boolean terraformValidate = false        // fmt -check + init -backend=false + validate
    String terraformImage = 'hashicorp/terraform:1.17.2'   // >= 1.10: use_lockfile needs it
    // DEV only until the first real run is validated (STAGE/PROD are added later):
    // each root needs ~772 MB of providers, shared through the plugin cache.
    List<String> terraformRoots = ['infra/terraform/envs/dev']
    String terraformFmtPath = 'infra/terraform'
    int terraformValidateTimeout = 15
    // Free space required in the workspace before running any Terraform command.
    int terraformMinFreeSpaceMB = 1500

    boolean trivyScan = false                // trivy config, blocks on HIGH/CRITICAL
    // Image of the Trivy TOOL (the scanner itself), used by the IaC scan AND by
    // the image scan. It is NOT the image being scanned: that one is built by
    // publishImages and passed as `ref` to trivyImageScan.
    String trivyImage = 'aquasec/trivy:0.76.2'
    List<String> trivyPaths = ['infra/terraform']
    String trivySeverity = 'HIGH,CRITICAL'
    int trivyTimeout = 15

    // Vulnerability scan of the BUILT images (Trivy Image): opt-in, blocking, and
    // runs inside "Publish images" BETWEEN `docker build` and `docker push`, so a
    // HIGH/CRITICAL finding never reaches the registry. It reads the image from
    // the local Docker daemon through the socket and needs no credentials.
    // Partial publication is accepted: a missing image fails at deploy time.
    boolean trivyImageScan = false
    String trivyImageSeverity = 'HIGH,CRITICAL'        // configured apart from the IaC scan
    List<String> trivyImageBranches = ['dev', 'main']  // ⊆ publishBranches; PRs never publish
    int trivyImageTimeout = 15
    String trivyImageIgnoreFile = '.trivyignore.yaml'  // same file as the IaC scan

    // Terraform plan against the REAL S3 backend (plan only: no apply, no
    // artifact). Off by default because it needs AWS credentials and contacts
    // the backend; enabling it never changes the behaviour of the other stages.
    boolean terraformPlan = false
    // Single root on purpose: it must NOT follow terraformRoots (a root added
    // to the validate list would otherwise start being planned automatically).
    String terraformPlanRoot = 'infra/terraform/envs/dev'
    // Only the dev branch plans: PRs and any other branch never receive the
    // AWS credential (the stage gate and this list are both required).
    List<String> terraformPlanBranches = ['dev']
    String terraformAwsCredentialsId = 'aws-terraform-credentials'
    String terraformAwsRegion = 'us-east-1'
    int terraformPlanTimeout = 20            // stage budget AND per-command timeout

    // Terraform apply (DEV only in this phase: STAGE/PROD stay disabled).
    // Off by default and gated by flag AND branch, so PRs never receive the AWS
    // credential. The stage budget is 2x the command timeout (init + apply).
    boolean terraformApply = false
    // Single root on purpose, like terraformPlanRoot: it must not follow the
    // other lists, so enabling stage/prod is always an explicit decision.
    String terraformApplyRoot = 'infra/terraform/envs/dev'
    List<String> terraformApplyBranches = ['dev']
    int terraformApplyTimeout = 30

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
        this.dockerCleanup = c.dockerCleanup != null ? c.dockerCleanup as boolean : this.dockerCleanup
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
        this.terraformValidate = c.terraformValidate != null ? c.terraformValidate as boolean : this.terraformValidate
        this.terraformImage = c.terraformImage ?: this.terraformImage
        this.terraformRoots = c.terraformRoots ?: this.terraformRoots
        this.terraformFmtPath = c.terraformFmtPath ?: this.terraformFmtPath
        this.terraformValidateTimeout = c.terraformValidateTimeout ? c.terraformValidateTimeout as int : this.terraformValidateTimeout
        this.terraformMinFreeSpaceMB = c.terraformMinFreeSpaceMB ? c.terraformMinFreeSpaceMB as int : this.terraformMinFreeSpaceMB
        this.trivyScan = c.trivyScan != null ? c.trivyScan as boolean : this.trivyScan
        this.trivyImage = c.trivyImage ?: this.trivyImage
        this.trivyPaths = c.trivyPaths ?: this.trivyPaths
        this.trivySeverity = c.trivySeverity ?: this.trivySeverity
        this.trivyTimeout = c.trivyTimeout ? c.trivyTimeout as int : this.trivyTimeout
        this.trivyImageScan = c.trivyImageScan != null ? c.trivyImageScan as boolean : this.trivyImageScan
        this.trivyImageSeverity = c.trivyImageSeverity ?: this.trivyImageSeverity
        this.trivyImageBranches = c.trivyImageBranches ?: this.trivyImageBranches
        this.trivyImageTimeout = c.trivyImageTimeout ? c.trivyImageTimeout as int : this.trivyImageTimeout
        this.trivyImageIgnoreFile = c.trivyImageIgnoreFile ?: this.trivyImageIgnoreFile
        this.terraformPlan = c.terraformPlan != null ? c.terraformPlan as boolean : this.terraformPlan
        this.terraformPlanRoot = c.terraformPlanRoot ?: this.terraformPlanRoot
        this.terraformPlanBranches = c.terraformPlanBranches ?: this.terraformPlanBranches
        this.terraformAwsCredentialsId = c.terraformAwsCredentialsId ?: this.terraformAwsCredentialsId
        this.terraformAwsRegion = c.terraformAwsRegion ?: this.terraformAwsRegion
        this.terraformPlanTimeout = c.terraformPlanTimeout ? c.terraformPlanTimeout as int : this.terraformPlanTimeout
        this.terraformApply = c.terraformApply != null ? c.terraformApply as boolean : this.terraformApply
        this.terraformApplyRoot = c.terraformApplyRoot ?: this.terraformApplyRoot
        this.terraformApplyBranches = c.terraformApplyBranches ?: this.terraformApplyBranches
        this.terraformApplyTimeout = c.terraformApplyTimeout ? c.terraformApplyTimeout as int : this.terraformApplyTimeout
        this.buildTimeout = c.buildTimeout ? c.buildTimeout as int : this.buildTimeout
        this.testTimeout = c.testTimeout ? c.testTimeout as int : this.testTimeout
        this.integrationTimeout = c.integrationTimeout ? c.integrationTimeout as int : this.integrationTimeout
        this.publishTimeout = c.publishTimeout ? c.publishTimeout as int : this.publishTimeout
        this.buildsToKeep = c.buildsToKeep ? c.buildsToKeep as int : this.buildsToKeep
        this.discordCredentialsId = c.discordCredentialsId != null ? c.discordCredentialsId : this.discordCredentialsId
    }
}
