def call(Map params = [:]) {
    String from = params.from ?: 'dev'
    String to = params.to
    String version = params.version
    boolean manual = params.manual ?: false
    String context = params.context
    String namespace = params.namespace
    String registry = params.registry
    Map overlayPaths = params.overlayPaths ?: [:]
    Map ingressUrls = params.ingressUrls ?: [:]
    List<Map> images = params.images ?: []
    List<String> deployments = params.deployments ?: []
    List<Map> verifyPaths = params.verifyPaths ?: []
    String kubeconfigCredentialId = params.kubeconfigCredentialId ?: "${to}-kubeconfig"
    int rolloutTimeout = params.rolloutTimeout ?: 300
    int retries = params.retries ?: 20
    int interval = params.intervalSeconds ?: 10
    int approvalTimeout = params.approvalTimeout ?: 120
    String evidenceFile = params.evidenceFile ?: 'promotion-record.txt'

    if (!to) {
        error 'promoteEnvironment: target environment is required'
    }
    if (!env.IMAGE_VERSION?.trim()) {
        error 'promoteEnvironment: env.IMAGE_VERSION from this build is required'
    }
    if (!version) {
        error 'promoteEnvironment: version argument is required for comparison'
    }
    if (version == 'latest') {
        error 'promoteEnvironment: promotions must use an identifiable version, not latest'
    }
    if (version != env.IMAGE_VERSION) {
        error "promoteEnvironment: version ${version} differs from env.IMAGE_VERSION ${env.IMAGE_VERSION}"
    }
    if (env.IMAGE_VERSION == 'latest') {
        error 'promoteEnvironment: promotions must use an identifiable version, not latest'
    }

    String overlayPath = overlayPaths[to] ?: "infra/k8s/overlays/${to}"
    String ingressUrl = ingressUrls[to]
    if (!ingressUrl?.trim()) {
        error "promoteEnvironment: ingressUrls['${to}'] is required"
    }
    ingressUrl = ingressUrl.replaceAll('/+$', '')

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
        approver = ((answer instanceof Map) ? "${answer.approvedBy}" : "${answer}").trim()
        if (!approver || approver == 'null') {
            error 'promoteEnvironment: manual approval did not identify an approver'
        }
        condition = "manual approval (input) by ${approver}"
        echo "Promotion approved by ${approver}"
    }

    echo "Promoting ${version}: ${from} -> ${to}"
    Map deployed = deployKubernetes(
        environment: to,
        context: context,
        namespace: namespace,
        registry: registry,
        overlayPath: overlayPath,
        kubeconfigCredentialId: kubeconfigCredentialId,
        images: images,
        deployments: deployments,
        rolloutTimeout: rolloutTimeout
    )

    verifyIngress(
        baseUrl: ingressUrl,
        checks: verifyPaths,
        retries: retries,
        intervalSeconds: interval
    )

    if (params.smokeTests != false) {
        smokeTests(
            baseUrl: ingressUrl,
            environment: to,
            loginCredentialsId: params.containsKey('smokeCredentialsId') ? params.smokeCredentialsId : 'e2e-credential'
        )
    }

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
Context      : ${context}
Namespace    : ${namespace}
Overlay      : ${overlayPath}
Manifest     : ${deployed.manifestArtifact}
Ingress      : ${ingressUrl}
Date (UTC)   : ${new java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'").with { it.timeZone = TimeZone.getTimeZone('UTC'); it.format(new Date())}}
"""
    appendEvidence(evidenceFile, record)
    archiveArtifacts artifacts: evidenceFile, allowEmptyArchive: false
    currentBuild.description = "images ${version} -> ${to}"

    return deployed
}

def appendEvidence(String file, String content) {
    String previous = fileExists(file) ? readFile(file) : ''
    writeFile file: file, text: previous + content + '\n'
}
