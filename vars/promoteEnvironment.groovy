/**
 * Promotes a version from one environment to the next one.
 *
 * Acceptance criteria of the promotion story:
 *   - Environments and promotion conditions are defined: the caller declares the
 *     route (dev -> stage -> prod) and whether the promotion needs a manual approval.
 *   - The promotion requires the previous validations: the pipeline runs the stages
 *     in order, so this step is only reached when build, tests, integration tests,
 *     deployment and E2E are green. `input` adds the manual gate for prod.
 *   - An identifiable version is used: the same image version published by the build
 *     (never "latest") is deployed in every environment.
 *   - Evidence is kept: a promotion record is archived with the build and the Jenkins
 *     log keeps who approved it and when.
 *
 * Usage:
 *   promoteEnvironment(from: 'dev', to: 'stage', version: '1.2.0-build.47.ab12cd3',
 *                      services: cfg.services)
 *
 *   promoteEnvironment(from: 'stage', to: 'prod', version: ..., manual: true,
 *                      approvalTimeout: 240, services: cfg.services)
 */
def call(Map params = [:]) {
    String from = params.from ?: 'dev'
    String to = params.to
    String version = params.version
    boolean manual = params.manual ?: false
    String credentialId = params.credentialId ?: "${to}-credential"
    List services = params.services ?: []
    int retries = params.retries ?: 20
    int interval = params.intervalSeconds ?: 10
    int approvalTimeout = params.approvalTimeout ?: 120
    String evidenceFile = params.evidenceFile ?: 'promotion-record.txt'

    if (!to) {
        error 'promoteEnvironment: target environment is required'
    }
    if (!version) {
        error 'promoteEnvironment: version is required'
    }
    if (version == 'latest') {
        error 'promoteEnvironment: promotions must use an identifiable version, not latest'
    }

    String approver = 'automatic (no approval required)'
    String condition = "automatic: previous validations passed (${from} is healthy and E2E green)"

    if (manual) {
        echo "Waiting for the promotion approval: ${from} -> ${to} (${version})"
        def answer = input(
            message: "Promote ${version} from ${from} to ${to}?\n\n" +
                     "Validations so far: build, unit tests, integration tests, " +
                     "deployment of ${from} and E2E tests passed.",
            ok: 'Promote',
            submitterParameter: 'approvedBy',
            timeout: approvalTimeout,
            timeUnit: 'MINUTES'
        )
        approver = (answer instanceof Map) ? "${answer.approvedBy}" : "${answer}"
        if (!approver || approver == 'null') {
            approver = 'unknown'
        }
        condition = "manual approval (input) by ${approver}"
        echo "Promotion approved by ${approver}"
    }

    echo "Promoting ${version}: ${from} -> ${to}"
    Map envCfg = deployEnvironment(
        environment: to,
        version: version,
        credentialId: credentialId,
        waitTimeout: params.waitTimeout
    )

    verifyServices(
        host: envCfg.HOST,
        services: services,
        retries: retries,
        intervalSeconds: interval
    )

    // Evidence of the promotion, archived with this build.
    String record = """CircleGuard promotion record
=============================
Build        : ${env.BUILD_URL ?: 'n/a'}
Build number : ${env.BUILD_NUMBER ?: 'n/a'}
Branch       : ${env.BRANCH_NAME ?: 'n/a'}
Commit       : ${env.GIT_COMMIT ?: 'n/a'}
Version      : ${version}
Route        : ${from} -> ${to}
Condition    : ${condition}
Approved by  : ${approver}
Date (UTC)   : ${new Date().format("yyyy-MM-dd'T'HH:mm:ss'Z'", TimeZone.getTimeZone('UTC'))}
"""
    appendEvidence(evidenceFile, record)
    archiveArtifacts artifacts: evidenceFile, allowEmptyArchive: false
    currentBuild.description = "images ${version} -> ${to}"

    return envCfg
}

/**
 * Appends a block to a file in the workspace (created on the first promotion).
 */
def appendEvidence(String file, String content) {
    String previous = fileExists(file) ? readFile(file) : ''
    writeFile file: file, text: previous + content + '\n'
}
