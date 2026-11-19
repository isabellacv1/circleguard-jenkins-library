import org.circleguard.ci.PipelineConfig

/**
 * CI pipeline for the CircleGuard monorepo (Gradle, 8 services).
 *
 * Usage in the Jenkinsfile:
 *   @Library('circleguard-pipeline-library@main') _
 *   circleguardPipeline(integrationTests: true, sonar: false)
 */
def call(Map rawConfig = [:]) {
    // Single source of truth for the whole-build budget: the same value feeds the
    // global timeout below and the remaining-time guard of the manual approval.
    // The clock starts HERE, before the pipeline begins, so the remaining time
    // it computes can only be smaller than the real one: the guard can refuse an
    // approval early, but can never let it start too late.
    final int pipelineTimeoutMinutes = 120
    final long pipelineStartedAtMs = System.currentTimeMillis()

    PipelineConfig cfg = new PipelineConfig(rawConfig)

    // The deployment runs the images produced by this build, so publishing them
    // first is mandatory: fail early with a clear message instead of failing at pull.
    if (cfg.deploy && !cfg.publish) {
        error 'circleguardPipeline: deploy requires publish=true (the deployment pulls the images published by this build)'
    }

    pipeline {
        agent any

        options {
            skipDefaultCheckout()
            timestamps()
            timeout(time: pipelineTimeoutMinutes, unit: 'MINUTES')
            buildDiscarder(logRotator(numToKeepStr: "${cfg.buildsToKeep}", artifactNumToKeepStr: '10'))
            disableConcurrentBuilds()
        }

        environment {
            GRADLE_OPTS = '-Dorg.gradle.daemon=false'
            DOCKER_BUILDKIT = '1'
        }

        stages {
            stage('Checkout') {
                steps {
                    checkout scm
                    sh 'git log -1 --format="%h %an: %s"'
                }
            }

            stage('Build') {
                options {
                    timeout(time: cfg.buildTimeout, unit: 'MINUTES')
                }
                steps {
                    gradlew 'assemble'
                }
            }

            stage('Tests') {
                options {
                    timeout(time: cfg.testTimeout, unit: 'MINUTES')
                }
                steps {
                    configureTestcontainers()
                    // --continue runs the tests of every service even if one of them fails
                    gradlew 'test --continue'
                }
            }

            stage('Integration tests') {
                when {
                    expression { cfg.integrationTests }
                }
                options {
                    timeout(time: cfg.integrationTimeout, unit: 'MINUTES')
                }
                steps {
                    configureTestcontainers()
                    gradlew 'integrationTest --continue'
                }
            }

            stage('SonarQube') {
                when {
                    expression { cfg.sonar }
                }
                steps {
                    sonarAnalysis(server: cfg.sonarServer, projectKey: cfg.sonarProjectKey)
                }
            }

            // Static validation of the Terraform code. Off by default (terraformValidate:
            // false): it needs no AWS credentials and never runs plan/apply, but it pulls
            // the pinned image on the first build.
            stage('Terraform validate') {
                when {
                    expression { cfg.terraformValidate }
                }
                options {
                    timeout(time: cfg.terraformValidateTimeout, unit: 'MINUTES')
                }
                steps {
                    script {
                        terraformValidate(
                            image: cfg.terraformImage,
                            roots: cfg.terraformRoots,
                            fmtPath: cfg.terraformFmtPath,
                            minFreeSpaceMB: cfg.terraformMinFreeSpaceMB
                        )
                    }
                }
            }

            // Trivy misconfiguration scan of the Terraform code: HIGH/CRITICAL findings
            // fail the build and the report is archived with it. Off by default.
            stage('Trivy IaC') {
                when {
                    expression { cfg.trivyScan }
                }
                options {
                    timeout(time: cfg.trivyTimeout, unit: 'MINUTES')
                }
                steps {
                    script {
                        trivyScan(
                            image: cfg.trivyImage,
                            paths: cfg.trivyPaths,
                            severity: cfg.trivySeverity
                        )
                    }
                }
            }

            // Terraform plan against the real S3 backend: the saved plan is not
            // archived and is applied by the next stage, in the SAME build.
            // DEV only: the flag AND the branch are both required, so PRs and
            // any other branch never receive the AWS credential.
            stage('Terraform plan') {
                when {
                    expression { cfg.terraformPlan && cfg.terraformPlanBranches.contains(env.BRANCH_NAME) }
                }
                options {
                    timeout(time: cfg.terraformPlanTimeout, unit: 'MINUTES')
                }
                steps {
                    script {
                        Map plan = terraformPlan(
                            image: cfg.terraformImage,
                            root: cfg.terraformPlanRoot,
                            credentialsId: cfg.terraformAwsCredentialsId,
                            region: cfg.terraformAwsRegion,
                            minFreeSpaceMB: cfg.terraformMinFreeSpaceMB,
                            timeout: cfg.terraformPlanTimeout
                        )
                        // Persisted so the apply stage can prove that the plan it
                        // consumes was produced by THIS build and this revision.
                        // The SHA-256 is the value a future approval (E4) binds to.
                        env.TF_PLAN_BUILD = env.BUILD_NUMBER
                        env.TF_PLAN_ROOT = plan.root
                        env.TF_PLAN_FILE = plan.planFile
                        env.TF_PLAN_INFO = plan.planInfo
                        env.TF_PLAN_SHA256 = plan.sha256
                        env.TF_PLAN_CHANGES = plan.changes.toString()
                    }
                }
            }

            // PROD plan: the same step as DEV, but for the PROD root. The root
            // is never chosen freely: terraformTarget() maps 'main' to
            // terraformApplyProdRoot and refuses any other branch/root pairing.
            stage('Terraform plan PROD') {
                when {
                    expression {
                        cfg.terraformApplyProd && cfg.terraformPlan &&
                        terraformTarget(cfg, env.BRANCH_NAME)?.name == 'prod'
                    }
                }
                options {
                    timeout(time: cfg.terraformPlanTimeout, unit: 'MINUTES')
                }
                steps {
                    script {
                        Map target = terraformTarget(cfg, env.BRANCH_NAME)
                        Map plan = terraformPlan(
                            image: cfg.terraformImage,
                            root: target.root,
                            credentialsId: cfg.terraformAwsCredentialsId,
                            region: cfg.terraformAwsRegion,
                            minFreeSpaceMB: cfg.terraformMinFreeSpaceMB,
                            timeout: cfg.terraformPlanTimeout
                        )
                        // Same contract as the DEV plan stage above: the apply
                        // stage validates every one of these before touching AWS.
                        env.TF_PLAN_BUILD = env.BUILD_NUMBER
                        env.TF_PLAN_ROOT = plan.root
                        env.TF_PLAN_FILE = plan.planFile
                        env.TF_PLAN_INFO = plan.planInfo
                        env.TF_PLAN_SHA256 = plan.sha256
                        env.TF_PLAN_CHANGES = plan.changes.toString()
                    }
                }
            }

            // Manual approval of the PROD infrastructure, between the plan and
            // the apply. It runs only when BOTH approval switches are on, only
            // for the PROD target, and only when the plan has changes; and only
            // while the build still has a full approval window left.
            // A failed or interrupted approval stops the pipeline here: the
            // stages below never run (nothing is swallowed in this stage).
            stage('Terraform approval') {
                when {
                    expression {
                        cfg.terraformApplyProd && cfg.terraformApproval && cfg.terraformApprovalProd &&
                        terraformTarget(cfg, env.BRANCH_NAME)?.name == 'prod' &&
                        env.TF_PLAN_CHANGES == 'true'
                    }
                }
                options {
                    timeout(time: cfg.terraformApprovalTimeout, unit: 'MINUTES')
                }
                steps {
                    script {
                        // Fail BEFORE showing the input when the build budget is
                        // too short for a full approval window.
                        requireApprovalTimeLeft(pipelineStartedAtMs, pipelineTimeoutMinutes,
                                                cfg.terraformApprovalTimeout)
                        Map target = terraformTarget(cfg, env.BRANCH_NAME)
                        terraformApproval(
                            root: target.root,
                            submitter: cfg.terraformApprovalSubmitter,
                            timeout: cfg.terraformApprovalTimeout,
                            maxAgeMinutes: cfg.terraformApprovalMaxAgeMinutes
                        )
                        // Binds this approval to the PROD target of this build:
                        // the apply stage below refuses to run without it.
                        env.TF_APPROVED_TARGET = target.name
                    }
                }
            }

            // Applies the plan produced by the previous stage in the SAME build.
            // DEV only (flag AND branch): PRs never receive the AWS credential.
            // The stage budget is 2x the command timeout (init + apply).
            stage('Terraform apply') {
                when {
                    expression { cfg.terraformApply && cfg.terraformApplyBranches.contains(env.BRANCH_NAME) }
                }
                options {
                    timeout(time: cfg.terraformApplyTimeout * 2, unit: 'MINUTES')
                }
                steps {
                    script {
                        terraformApply(
                            image: cfg.terraformImage,
                            root: cfg.terraformApplyRoot,
                            credentialsId: cfg.terraformAwsCredentialsId,
                            region: cfg.terraformAwsRegion,
                            minFreeSpaceMB: cfg.terraformMinFreeSpaceMB,
                            timeout: cfg.terraformApplyTimeout,
                            // DEV never requires an approval (the PROD stage below does)
                            requireApproval: false
                        )
                    }
                }
            }

            // PROD apply: only after a valid approval of THIS build. The step
            // re-validates build, commit, root, both hashes and both ages before
            // it binds the credential, so an approval of another plan or another
            // build can never be reused here.
            stage('Terraform apply PROD') {
                when {
                    expression {
                        cfg.terraformApplyProd && env.TF_PLAN_CHANGES == 'true' &&
                        terraformTarget(cfg, env.BRANCH_NAME)?.name == 'prod'
                    }
                }
                options {
                    timeout(time: cfg.terraformApplyTimeout * 2, unit: 'MINUTES')
                }
                steps {
                    script {
                        if (env.TF_APPROVED_TARGET != 'prod') {
                            error 'Terraform apply PROD: no approval was recorded for this build ' +
                                  "(TF_APPROVED_TARGET='${env.TF_APPROVED_TARGET}'): enable " +
                                  'terraformApproval AND terraformApprovalProd and start a new ' +
                                  'build. Nothing will be applied.'
                        }
                        Map target = terraformTarget(cfg, env.BRANCH_NAME)
                        terraformApply(
                            image: cfg.terraformImage,
                            root: target.root,
                            credentialsId: cfg.terraformAwsCredentialsId,
                            region: cfg.terraformAwsRegion,
                            minFreeSpaceMB: cfg.terraformMinFreeSpaceMB,
                            timeout: cfg.terraformApplyTimeout,
                            requireApproval: true,
                            maxAgeMinutes: cfg.terraformApprovalMaxAgeMinutes
                        )
                    }
                }
            }

            stage('Publish images') {
                when {
                    expression { cfg.publish && cfg.publishBranches.contains(env.BRANCH_NAME) }
                }
                options {
                    timeout(time: cfg.publishTimeout, unit: 'MINUTES')
                }
                steps {
                    script {
                        String version = resolveVersion()
                        echo "Image version: ${version}"
                        // The deploy stages reuse exactly this version, so the
                        // environment always runs the images this build produced.
                        env.IMAGE_VERSION = version
                        currentBuild.description = "images ${version}"
                        publishImages(
                            registry: cfg.registry,
                            credentialsId: cfg.registryCredentialsId,
                            version: version,
                            images: cfg.images,
                            // Trivy Image (opt-in): scan between build and push
                            scanVulnerabilities: cfg.trivyImageScan,
                            trivyToolImage: cfg.trivyImage,
                            scanSeverity: cfg.trivyImageSeverity,
                            scanTimeout: cfg.trivyImageTimeout,
                            scanBranches: cfg.trivyImageBranches,
                            scanIgnoreFile: cfg.trivyImageIgnoreFile
                        )
                    }
                }
            }

            // HU-13: deploy of the published images to an AWS environment.
            stage('Deploy') {
                when {
                    expression { cfg.deploy && cfg.deployBranches.contains(env.BRANCH_NAME) }
                }
                options {
                    timeout(time: cfg.deployTimeout, unit: 'MINUTES')
                }
                steps {
                    script {
                        // The same version that was published (never "latest").
                        String version = env.IMAGE_VERSION ?: resolveVersion()
                        env.IMAGE_VERSION = version
                        String credentialId = cfg.deployCredentialId ?: "${cfg.environment}-credential"
                        Map envCfg = deployEnvironment(
                            environment: cfg.environment,
                            version: version,
                            credentialId: credentialId
                        )
                        env.DEPLOY_HOST = envCfg.HOST
                        currentBuild.description = "images ${version} -> ${cfg.environment}"
                    }
                }
            }

            // HU-13: the deployment is only accepted if every component answers.
            stage('Verify deployment') {
                when {
                    expression { cfg.deploy && cfg.deployBranches.contains(env.BRANCH_NAME) }
                }
                options {
                    timeout(time: cfg.verifyTimeout, unit: 'MINUTES')
                }
                steps {
                    verifyServices(
                        host: env.DEPLOY_HOST,
                        services: cfg.services,
                        retries: cfg.healthRetries,
                        intervalSeconds: cfg.healthIntervalSeconds
                    )
                }
            }

            // HU-15: functional smoke tests after the deployment. A deployment that does not
            // pass them is marked as failed and the results are kept in the build.
            stage('Smoke tests') {
                when {
                    expression { cfg.deploy && cfg.smokeTests && cfg.deployBranches.contains(env.BRANCH_NAME) }
                }
                options {
                    timeout(time: cfg.smokeTimeout, unit: 'MINUTES')
                }
                steps {
                    smokeTests(
                        host: env.DEPLOY_HOST,
                        environment: cfg.environment,
                        loginCredentialsId: cfg.smokeCredentialsId
                    )
                }
            }

            // HU-14: end to end tests against the deployed dev environment.
            // They are the condition to promote the version to stage.
            stage('E2E tests') {
                when {
                    expression { cfg.deploy && cfg.e2e && cfg.deployBranches.contains(env.BRANCH_NAME) }
                }
                options {
                    timeout(time: cfg.e2eTimeout, unit: 'MINUTES')
                }
                steps {
                    // A declarative steps{} block only accepts steps, so the
                    // variables must live inside a script{} block.
                    script {
                        String base = "http://${env.DEPLOY_HOST}"
                        runE2E(
                            baseUrl: "${base}:8081",
                            authBaseUrl: "${base}:8180",
                            gatewayBaseUrl: "${base}:8087",
                            credentialsId: cfg.e2eCredentialsId,
                            image: cfg.e2eImage,
                            timeoutMinutes: cfg.e2eTimeout
                        )
                    }
                }
            }

            // HU-14: dev -> stage, only after every previous validation passed.
            stage('Promote to stage') {
                when {
                    expression { cfg.deploy && cfg.promote && cfg.deployBranches.contains(env.BRANCH_NAME) }
                }
                options {
                    timeout(time: cfg.approvalTimeout, unit: 'MINUTES')
                }
                steps {
                    script {
                        Map envCfg = promoteEnvironment(
                            from: 'dev',
                            to: 'stage',
                            version: env.IMAGE_VERSION,
                            manual: cfg.stageApproval,
                            approvalTimeout: cfg.approvalTimeout,
                            services: cfg.services,
                            smokeTests: cfg.smokeTests,
                            smokeCredentialsId: cfg.smokeCredentialsId,
                            retries: cfg.healthRetries,
                            intervalSeconds: cfg.healthIntervalSeconds,
                            evidenceFile: cfg.promotionRecordFile
                        )
                        env.STAGE_HOST = envCfg.HOST
                    }
                }
            }

            // HU-14: stage -> prod, always behind a manual approval (input).
            stage('Promote to prod') {
                when {
                    expression { cfg.deploy && cfg.promote && cfg.deployBranches.contains(env.BRANCH_NAME) }
                }
                options {
                    timeout(time: cfg.approvalTimeout, unit: 'MINUTES')
                }
                steps {
                    script {
                        promoteEnvironment(
                            from: 'stage',
                            to: 'prod',
                            version: env.IMAGE_VERSION,
                            manual: cfg.prodApproval,
                            approvalTimeout: cfg.approvalTimeout,
                            services: cfg.services,
                            smokeTests: cfg.smokeTests,
                            smokeCredentialsId: cfg.smokeCredentialsId,
                            retries: cfg.healthRetries,
                            intervalSeconds: cfg.healthIntervalSeconds,
                            evidenceFile: cfg.promotionRecordFile
                        )
                    }
                }
            }
        }

        post {
            always {
                publishTestReports()
                // Remove BuildKit cache, dangling images and test leftovers (never fails the build)
                script {
                    if (cfg.dockerCleanup) {
                        dockerCleanup()
                    }
                    // PR and feature branch workspaces are not reused, delete them to save disk.
                    // dev and main keep theirs so the next build is faster.
                    if (!(env.BRANCH_NAME in ['dev', 'main'])) {
                        deleteDir()
                    }
                }
            }
            success {
                echo 'Build and tests passed.'
            }
            failure {
                echo 'Pipeline failed. Check the failed stage and the Tests tab for details.'
                script {
                    if (cfg.discordCredentialsId) {
                        notifyDiscord(
                            credentialsId: cfg.discordCredentialsId,
                            status: 'FAILURE'
                        )
                    }
                }
            }
        }
    }
}

/**
 * Terraform target of a branch, resolved ONLY from the configuration, so a
 * branch and a root can never be combined arbitrarily:
 *
 *   - a branch in terraformApplyProdBranches drives the PROD target (root
 *     terraformApplyProdRoot) and is only accepted when it is 'main';
 *   - a branch in terraformApplyBranches drives the DEV target (root
 *     terraformApplyRoot);
 *   - anything else (PRs, feature branches) drives no target and returns null.
 *
 * Fails when one branch is configured for both targets or when PROD would be
 * selected from a branch other than 'main'.
 */
Map terraformTarget(PipelineConfig cfg, String branch) {
    if (!branch) {
        return null
    }
    boolean prodBranch = cfg.terraformApplyProdBranches.contains(branch)
    boolean devBranch = cfg.terraformApplyBranches.contains(branch)
    if (prodBranch && devBranch) {
        error "circleguardPipeline: branch '${branch}' belongs to BOTH terraformApplyBranches " +
              'and terraformApplyProdBranches: refusing to pick a root arbitrarily'
    }
    if (prodBranch && branch != 'main') {
        error "circleguardPipeline: the PROD Terraform target is only allowed from 'main' " +
              "(not from '${branch}'): refusing to select ${cfg.terraformApplyProdRoot}"
    }
    if (prodBranch) {
        return [name: 'prod', root: cfg.terraformApplyProdRoot]
    }
    if (devBranch) {
        return [name: 'dev', root: cfg.terraformApplyRoot]
    }
    return null
}

/**
 * Fails when the build does not have a full approval window left, so the input
 * is never shown (and no apply can follow) when the global timeout would abort
 * the build in the middle of the approval.
 *
 * The DECISION is taken with exact milliseconds (budget vs elapsed vs approval
 * window): minutes are only used to word the message, so a partial minute can
 * never be mistaken for a full one. The clock is a plain
 * System.currentTimeMillis() anchored at the very start of call(): no Jenkins
 * API is involved, and because that anchor is never later than the start of the
 * global `timeout`, the remaining time computed here is always <= the real one —
 * conservative: it can refuse early, never late.
 *
 * `nowMs` exists only so the boundary cases can be tested deterministically;
 * production omits it and uses the real clock.
 */
void requireApprovalTimeLeft(long startedAtMs, int budgetMinutes, int approvalMinutes, Long nowMs = null) {
    if (budgetMinutes <= 0) {
        error "Terraform approval: the build budget must be > 0 minutes, got ${budgetMinutes}"
    }
    if (approvalMinutes <= 0) {
        error "Terraform approval: the approval window must be > 0 minutes, got ${approvalMinutes}"
    }
    long now = (nowMs != null) ? nowMs : System.currentTimeMillis()
    long elapsedMs = now - startedAtMs
    if (elapsedMs < 0) {
        error "Terraform approval: the elapsed time is negative (${elapsedMs} ms): " +
              'refusing to estimate the remaining build budget'
    }
    long budgetMs = ((long) budgetMinutes) * 60_000L
    long approvalMs = ((long) approvalMinutes) * 60_000L
    long remainingMs = budgetMs - elapsedMs
    if (remainingMs < approvalMs) {
        error "Terraform approval: " +
              "${java.util.concurrent.TimeUnit.MILLISECONDS.toMinutes(remainingMs)} minute(s) left " +
              "of the ${budgetMinutes}-minute build budget, less than the ${approvalMinutes} " +
              'required for a full approval: NOT requesting the approval and NOT applying ' +
              'anything (start a new build)'
    }
    echo "terraformApproval: " +
         "${java.util.concurrent.TimeUnit.MILLISECONDS.toMinutes(remainingMs)} minute(s) left " +
         "of the ${budgetMinutes}-minute build budget"
}
