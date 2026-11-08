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
        }

        post {
            always {
                publishTestReports()
            }
            success {
                echo 'Build and tests passed.'
            }
            failure {
                echo 'Pipeline failed. Check the failed stage and the Tests tab for details.'
                if (cfg.discordCredentialsId) {
                    notifyDiscord(credentialsId: cfg.discordCredentialsId, status: 'FAILURE')
                }
            }
        }
    }
}
