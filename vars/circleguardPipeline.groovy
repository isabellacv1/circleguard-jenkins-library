import org.circleguard.ci.PipelineConfig

/**
 * CI pipeline for the CircleGuard monorepo (Gradle, 8 services).
 *
 * Usage in the Jenkinsfile:
 *   @Library('circleguard-pipeline-library@main') _
 *   circleguardPipeline(integrationTests: true, sonar: false)
 */
def call(Map rawConfig = [:]) {
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
            timeout(time: 90, unit: 'MINUTES')
            buildDiscarder(logRotator(numToKeepStr: "${cfg.buildsToKeep}", artifactNumToKeepStr: '10'))
            disableConcurrentBuilds(abortPrevious: true)
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
                            images: cfg.images
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
