import com.cloudbees.groovy.cps.NonCPS

def call(Map params = [:]) {
    if (params.containsKey('version')) {
        error 'deployKubernetes: version must come from env.IMAGE_VERSION only'
    }

    String environment = params.environment ?: 'dev'
    String version = env.IMAGE_VERSION
    String context = params.context
    String namespace = params.namespace
    String registry = params.registry
    String overlayPath = params.overlayPath
    String kubeconfigCredentialId = params.kubeconfigCredentialId ?: "${environment}-kubeconfig"
    List<Map> images = params.images ?: []
    List<String> deployments = params.deployments ?: []
    int rolloutTimeout = params.rolloutTimeout ?: 300

    if (!version?.trim() || version == 'latest') {
        error 'deployKubernetes: env.IMAGE_VERSION must be a semantic version from this build'
    }
    if (!context?.trim()) {
        error 'deployKubernetes: context is required'
    }
    if (!namespace?.trim()) {
        error 'deployKubernetes: namespace is required'
    }
    if (namespace != 'circleguard') {
        error "deployKubernetes: manifests hardcode namespace 'circleguard'; namespace '${namespace}' is not supported"
    }
    if (!registry?.trim()) {
        error 'deployKubernetes: registry is required'
    }
    if (!overlayPath?.trim()) {
        error 'deployKubernetes: overlayPath is required'
    }
    if (!fileExists(overlayPath)) {
        error "deployKubernetes: overlay not found: ${overlayPath}"
    }
    if (images.size() != 9) {
        error "deployKubernetes: exactly nine images are required, got ${images.size()}"
    }
    if (deployments.size() != 9) {
        error "deployKubernetes: exactly nine deployments are required, got ${deployments.size()}"
    }

    String safeEnv = environment.replaceAll('[^A-Za-z0-9_.-]', '_')
    String suffix = "${safeEnv}-${env.BUILD_NUMBER ?: 'local'}"
    File overlayFile = new File(overlayPath)
    File parent = overlayFile.parentFile ?: new File('.')
    String tempDir = new File(parent, ".deploy-${suffix}").path
    String manifest = params.manifestArtifact ?: "k8s/rendered-${suffix}.yaml"
    String manifestParent = new File(manifest).parent ?: '.'

    withCredentials([file(credentialsId: kubeconfigCredentialId, variable: 'KUBECONFIG')]) {
        try {
            sh "mkdir -p ${q(manifestParent)}"
            sh "rm -rf ${q(tempDir)}"
            sh "cp -R ${q(overlayPath)} ${q(tempDir)}"

            images.each { Map image ->
                String name = image.name
                if (!name?.trim()) {
                    error 'deployKubernetes: every image needs a name'
                }
                String mapping = "${registry}/${name}=${registry}/${name}:${version}"
                sh "cd ${q(tempDir)} && kustomize edit set image ${q(mapping)}"
            }

            // kustomize renders local files only: no cluster access, therefore no
            // --context/--namespace. Every command below that touches the cluster
            // passes both flags explicitly.
            String renderedManifest = sh(script: "kubectl kustomize ${q(tempDir)}", returnStdout: true)
            validateRenderedManifest(renderedManifest, environment, overlayPath)
            writeFile file: manifest, text: renderedManifest
            archiveArtifacts artifacts: manifest, allowEmptyArchive: false

            String active = sh(script: 'kubectl config current-context', returnStdout: true).trim()
            if (active != context) {
                error "deployKubernetes: expected kubectl context '${context}', got '${active}'"
            }

            sh "kubectl --context ${q(context)} --namespace ${q(namespace)} apply --dry-run=server -k ${q(tempDir)}"
            sh "kubectl --context ${q(context)} --namespace ${q(namespace)} apply -k ${q(tempDir)}"
            echo "Applied ${environment} manifests from ${tempDir} (no prune)"

            deployments.each { String deployment ->
                sh "kubectl --context ${q(context)} --namespace ${q(namespace)} rollout status deployment/${deployment} --timeout=${rolloutTimeout}s"
            }
            echo "All ${deployments.size()} deployments rolled out in namespace ${namespace}"
        } finally {
            sh "rm -rf ${q(tempDir)} || true"
        }
    }

    return [environment     : environment,
            version         : version,
            context         : context,
            namespace       : namespace,
            registry        : registry,
            overlayPath     : tempDir,
            manifestArtifact: manifest,
            deployments     : deployments]
}

@NonCPS
private static String scalarValue(String raw) {
    String value = raw?.trim() ?: ''
    int comment = value.indexOf(' #')
    if (comment >= 0) {
        value = value.substring(0, comment).trim()
    }
    if (value.length() >= 2 &&
        ((value.startsWith("'") && value.endsWith("'")) ||
         (value.startsWith('"') && value.endsWith('"')))) {
        value = value.substring(1, value.length() - 1)
    }
    return value
}

@NonCPS
static List<Map<String, String>> parseRenderedManifest(String manifest) {
    List<Map<String, String>> resources = []
    if (!manifest?.trim()) {
        return resources
    }
    Map<String, String> current = null
    boolean inMetadata = false
    manifest.readLines().each { String rawLine ->
        String line = rawLine.replace('\r', '')
        String trimmed = line.trim()
        if (trimmed == '---') {
            if (current?.kind) {
                resources << current
            }
            current = null
            inMetadata = false
            return
        }
        if (!trimmed || trimmed.startsWith('#')) {
            return
        }
        if (line.startsWith('apiVersion:')) {
            if (current == null) {
                current = [:]
            }
            inMetadata = false
            return
        }
        if (line.startsWith('kind:')) {
            if (current?.kind) {
                resources << current
            }
            current = [kind: scalarValue(line.substring('kind:'.length()))]
            inMetadata = false
            return
        }
        if (line.startsWith('metadata:')) {
            if (current == null) {
                current = [:]
            }
            inMetadata = true
            return
        }
        if (inMetadata && line.startsWith('  ') && !line.startsWith('    ')) {
            String field = line.trim()
            if (field.startsWith('name:')) {
                current.name = scalarValue(field.substring('name:'.length()))
            } else if (field.startsWith('namespace:')) {
                current.namespace = scalarValue(field.substring('namespace:'.length()))
            }
            return
        }
        if (!line.startsWith(' ') && !line.startsWith('\t')) {
            inMetadata = false
        }
    }
    if (current?.kind) {
        resources << current
    }
    return resources
}

@NonCPS
static void validateRenderedManifest(String manifest, String environment, String overlayPath) {
    List<Map<String, String>> resources = parseRenderedManifest(manifest)
    if (resources.isEmpty()) {
        throw new IllegalArgumentException(
            "deployKubernetes: render of ${overlayPath} is empty; refusing to apply an empty manifest")
    }
    List<String> allowedKinds = ['ConfigMap', 'Deployment', 'Service', 'Ingress', 'PersistentVolumeClaim']
    String appNamespace = 'circleguard'
    List<String> problems = []
    resources.eachWithIndex { Map<String, String> resource, int index ->
        String kind = resource.kind ?: '<unknown>'
        String name = resource.name ?: '<unnamed>'
        String namespace = resource.namespace
        if (!allowedKinds.contains(kind)) {
            problems << "resource ${index + 1} ${kind}/${name}: kind '${kind}' is outside the Jenkins application allowlist"
        }
        if (!namespace) {
            problems << "resource ${index + 1} ${kind}/${name}: metadata.namespace is missing"
        } else if (namespace != appNamespace) {
            problems << "resource ${index + 1} ${kind}/${name}: namespace '${namespace}' is outside '${appNamespace}'"
        }
    }
    if (problems) {
        throw new IllegalArgumentException(
            "deployKubernetes: render of ${overlayPath} for ${environment} is outside the '${appNamespace}' application scope:\n - " +
            problems.join('\n - '))
    }
}

String q(String value) {
    return "'" + value.replace("'", "'\\''") + "'"
}
