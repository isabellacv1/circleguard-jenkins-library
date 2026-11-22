package org.circleguard.ci

import com.cloudbees.groovy.cps.NonCPS

/**
 * Parameters accepted by circleguardPipeline().
 * Every value has a default, so the Jenkinsfile only sets what changes.
 */
class PipelineConfig implements Serializable {
    static final String K8S_MANIFEST_NAMESPACE = 'circleguard'

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
        [name: 'circleguard/notification-service', dockerfile: 'services/circleguard-notification-service/Dockerfile', context: '.'],
        [name: 'circleguard/form-service',      dockerfile: 'services/circleguard-form-service/Dockerfile',      context: '.'],
        [name: 'circleguard/gateway-service',   dockerfile: 'services/circleguard-gateway-service/Dockerfile',   context: '.'],
        [name: 'circleguard/dashboard-service', dockerfile: 'services/circleguard-dashboard-service/Dockerfile', context: '.'],
        [name: 'circleguard/file-service',      dockerfile: 'services/circleguard-file-service/Dockerfile',      context: '.'],
        [name: 'circleguard/web',               dockerfile: 'mobile/Dockerfile',                                 context: 'mobile'],
    ]

    // Kubernetes deployment replaces the former SSH/Compose path.
    boolean deploy = false
    String environment = 'dev'
    List<String> deployBranches = ['dev']
    String kubeconfigCredentialId = null
    String k8sTokenCredentialId = null
    String k8sContext = ''
    String k8sNamespace = 'circleguard'
    Map<String, String> k8sContexts = [:]
    Map<String, String> k8sNamespaces = [:]
    String k8sRegistry = '10.20.1.230:8082'
    Map<String, String> k8sOverlayPaths = [:]
    Map<String, String> k8sIngressUrls = [:]
    List<String> k8sDeployments = [
        'circleguard-web',
        'circleguard-auth-service',
        'circleguard-identity-service',
        'circleguard-promotion-service',
        'circleguard-notification-service',
        'circleguard-form-service',
        'circleguard-gateway-service',
        'circleguard-dashboard-service',
        'circleguard-file-service',
    ]
    List<Map> k8sVerifyPaths = [
        [name: 'web home',               path: '/',                                                                  expected: '200'],
        [name: 'web runtime config',     path: '/env-config.js',                                                     expected: '200'],
        [name: 'gateway validates token', method: 'POST', path: '/api/v1/gate/validate', body: '{"token":"invalid"}', expected: '200'],
        [name: 'form pending surveys',   path: '/api/v1/certificates/pending',                                       expected: '200'],
        [name: 'promotion health stats', path: '/api/v1/health-status/stats',                                        expected: '200'],
        [name: 'identity requires auth', path: '/api/v1/identities/lookup/00000000-0000-0000-0000-000000000000',     expected: '401 403'],
    ]
    int deployTimeout = 20
    int verifyTimeout = 15
    int verifyRetries = 20
    int verifyIntervalSeconds = 10
    int k8sRolloutTimeout = 300

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

    // Terraform approval (E4, S1: configuration only, no step yet): the manual
    // gate that will sit between the plan and the apply of an environment that
    // requires it (PROD). Every switch is OFF by default, so nothing runs and
    // nothing can be approved by accident until the approval step exists.
    boolean terraformApproval = false
    int terraformApprovalTimeout = 30           // minutes the approver has to answer
    String terraformApprovalSubmitter = 'admin' // users/groups allowed to approve
    int terraformApprovalMaxAgeMinutes = 60     // a plan older than this is rejected

    // PROD target (E4): declared so the configuration is complete, but INERT:
    // applying PROD and approving PROD are two independent switches, both off.
    String terraformApplyProdRoot = 'infra/terraform/envs/prod'
    List<String> terraformApplyProdBranches = ['main']
    boolean terraformApplyProd = false
    boolean terraformApprovalProd = false

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
        this.kubeconfigCredentialId = c.kubeconfigCredentialId ?: (c.containsKey('kubeconfigCredentialId') ? c.kubeconfigCredentialId : null)
        this.k8sTokenCredentialId = c.k8sTokenCredentialId ?: (c.containsKey('k8sTokenCredentialId') ? c.k8sTokenCredentialId : null)
        this.k8sContext = c.k8sContext ?: this.k8sContext
        this.k8sNamespace = c.k8sNamespace ?: this.k8sNamespace
        this.k8sContexts = c.k8sContexts ?: this.k8sContexts
        this.k8sNamespaces = c.k8sNamespaces ?: this.k8sNamespaces
        this.k8sRegistry = c.k8sRegistry ?: this.k8sRegistry
        this.k8sOverlayPaths = c.k8sOverlayPaths ?: this.k8sOverlayPaths
        this.k8sIngressUrls = c.k8sIngressUrls ?: this.k8sIngressUrls
        this.k8sDeployments = c.k8sDeployments ?: this.k8sDeployments
        this.k8sVerifyPaths = c.k8sVerifyPaths ?: this.k8sVerifyPaths
        this.deployTimeout = c.deployTimeout ? c.deployTimeout as int : this.deployTimeout
        this.verifyTimeout = c.verifyTimeout ? c.verifyTimeout as int : this.verifyTimeout
        this.verifyRetries = c.verifyRetries ? c.verifyRetries as int : this.verifyRetries
        this.verifyIntervalSeconds = c.verifyIntervalSeconds ? c.verifyIntervalSeconds as int : this.verifyIntervalSeconds
        this.k8sRolloutTimeout = c.k8sRolloutTimeout ? c.k8sRolloutTimeout as int : this.k8sRolloutTimeout
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
        this.terraformApproval = c.terraformApproval != null ? c.terraformApproval as boolean : this.terraformApproval
        // containsKey + null check ONLY for the validated values: `0` and '' are
        // falsy in Groovy, so the `?:` pattern would silently replace them with
        // the defaults and the validation at the end would never see them.
        this.terraformApprovalTimeout = (c.containsKey('terraformApprovalTimeout') && c.terraformApprovalTimeout != null) ? c.terraformApprovalTimeout as int : this.terraformApprovalTimeout
        this.terraformApprovalSubmitter = (c.containsKey('terraformApprovalSubmitter') && c.terraformApprovalSubmitter != null) ? c.terraformApprovalSubmitter as String : this.terraformApprovalSubmitter
        this.terraformApprovalMaxAgeMinutes = (c.containsKey('terraformApprovalMaxAgeMinutes') && c.terraformApprovalMaxAgeMinutes != null) ? c.terraformApprovalMaxAgeMinutes as int : this.terraformApprovalMaxAgeMinutes
        this.terraformApplyProdRoot = c.terraformApplyProdRoot ?: this.terraformApplyProdRoot
        this.terraformApplyProdBranches = c.terraformApplyProdBranches ?: this.terraformApplyProdBranches
        this.terraformApplyProd = c.terraformApplyProd != null ? c.terraformApplyProd as boolean : this.terraformApplyProd
        this.terraformApprovalProd = c.terraformApprovalProd != null ? c.terraformApprovalProd as boolean : this.terraformApprovalProd
        this.buildTimeout = c.buildTimeout ? c.buildTimeout as int : this.buildTimeout
        this.testTimeout = c.testTimeout ? c.testTimeout as int : this.testTimeout
        this.integrationTimeout = c.integrationTimeout ? c.integrationTimeout as int : this.integrationTimeout
        this.publishTimeout = c.publishTimeout ? c.publishTimeout as int : this.publishTimeout
        this.buildsToKeep = c.buildsToKeep ? c.buildsToKeep as int : this.buildsToKeep
        this.discordCredentialsId = c.discordCredentialsId != null ? c.discordCredentialsId : this.discordCredentialsId

        if (this.deploy) {
            if (!this.k8sRegistry?.trim()) {
                throw new IllegalArgumentException('PipelineConfig: k8sRegistry must not be empty')
            }
            if (this.images.size() != 9) {
                throw new IllegalArgumentException('PipelineConfig: images must declare the nine application images')
            }
            if (this.k8sDeployments.size() != 9) {
                throw new IllegalArgumentException('PipelineConfig: k8sDeployments must name the nine application Deployments')
            }
            if (this.k8sVerifyPaths.isEmpty()) {
                throw new IllegalArgumentException('PipelineConfig: k8sVerifyPaths must not be empty')
            }

            List<String> k8sEnvironments = [this.environment]
            if (this.promote) {
                k8sEnvironments << 'stage' << 'prod'
            }
            this.k8sNamespaces.each { String envName, Object configured ->
                if (configured?.toString()?.trim() && configured.toString().trim() != K8S_MANIFEST_NAMESPACE) {
                    throw new IllegalArgumentException(
                            "PipelineConfig: manifests hardcode namespace '${K8S_MANIFEST_NAMESPACE}'; " +
                            "k8sNamespaces['${envName}'] cannot select another namespace")
                }
            }
            k8sEnvironments.unique().each { String environmentName ->
                if (!contextFor(environmentName)) {
                    throw new IllegalArgumentException(
                            "PipelineConfig: k8sContext is required when deploy=true (environment=${environmentName})")
                }
                String configuredNamespace = namespaceFor(environmentName)
                if (!configuredNamespace) {
                    throw new IllegalArgumentException(
                            "PipelineConfig: k8sNamespace is required for environment=${environmentName}")
                }
                if (configuredNamespace != K8S_MANIFEST_NAMESPACE) {
                    throw new IllegalArgumentException(
                            "PipelineConfig: manifests hardcode namespace '${K8S_MANIFEST_NAMESPACE}'; " +
                            "namespace '${configuredNamespace}' is invalid for environment=${environmentName}")
                }
                String ingress = this.k8sIngressUrls[environmentName]
                if (!ingress?.trim()) {
                    throw new IllegalArgumentException(
                            "PipelineConfig: k8sIngressUrls['${environmentName}'] is required when deploy=true")
                }
            }
        }

        // Fail fast on an invalid approval configuration: a timeout or an age of
        // 0 minutes, or an empty submitter, would make the approval impossible to
        // grant (or meaningless). Better to refuse the configuration than to run
        // a stage that can never be approved. These checks run for every build,
        // even with the approval disabled, so a typo is caught early.
        if (this.terraformApprovalTimeout <= 0) {
            throw new IllegalArgumentException(
                    'PipelineConfig: terraformApprovalTimeout must be > 0 minutes, got ' +
                    this.terraformApprovalTimeout)
        }
        if (this.terraformApprovalMaxAgeMinutes <= 0) {
            throw new IllegalArgumentException(
                    'PipelineConfig: terraformApprovalMaxAgeMinutes must be > 0 minutes, got ' +
                    this.terraformApprovalMaxAgeMinutes)
        }
        if (this.terraformApprovalSubmitter == null || !this.terraformApprovalSubmitter.trim()) {
            throw new IllegalArgumentException(
                    'PipelineConfig: terraformApprovalSubmitter must not be empty')
        }
    }

    @NonCPS
    String contextFor(String environmentName) {
        String configured = this.k8sContexts[environmentName] ?: this.k8sContext
        return configured?.trim() ?: ''
    }

    @NonCPS
    String namespaceFor(String environmentName) {
        String configured = this.k8sNamespaces[environmentName] ?: this.k8sNamespace
        return configured?.trim() ?: ''
    }
}
