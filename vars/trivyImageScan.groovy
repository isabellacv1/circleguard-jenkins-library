/**
 * Scans a LOCALLY BUILT image with Trivy and BLOCKS the build when a
 * HIGH/CRITICAL vulnerability is found (Trivy Image).
 *
 * It is called by `publishImages` between `docker build` and `docker push`, so a
 * vulnerable image never reaches the registry. Partial publication is accepted:
 * the version is unique to the build (never "latest") and the deployment needs
 * every image of that version, so a missing image fails at deploy time.
 *
 * How the local image is read (no new service, no Dockerfile change):
 *
 *   - the image is tagged in the Docker daemon of the host
 *     (`localhost:8082/<name>:<version>`), so the container talks to the daemon
 *     through a bind mount of /var/run/docker.sock and `--image-src docker`
 *     restricts Trivy to that local daemon: it never tries to pull
 *     `localhost:8082` from inside the container (where `localhost` would be
 *     the container itself) nor to reach any registry. (`trivy image` has no
 *     `--pull` flag: 0.76.2 rejects it with *"unknown flag: --pull"*);
 *   - the container runs with the uid/gid of the agent (`--user $(id -u):$(id -g)`),
 *     which is NOT the group that owns the socket (and Docker does not resolve
 *     supplementary groups for a numeric user), so the GID of the socket is read
 *     **at run time** with `stat -c '%g'` — never a fixed value, it differs per
 *     installation — and passed with `--group-add`. Without it the daemon answers
 *     *"permission denied while trying to connect to the docker API"*; if the GID
 *     cannot be read the command fails, so the step never scans without it;
 *   - the workspace is mounted with the same `volume-subpath` pattern as
 *     runInContainer, so the report is written into the workspace of the job (and
 *     archived by Jenkins) while the container never reaches `credentials.xml`,
 *     `secrets/` or the workspaces of the other jobs;
 *   - the Trivy database and cache live in the shared cache of the IaC scan
 *     (`/ws/.trivy-cache`), downloaded once and reused by both scans.
 *
 * No credentials are needed: the image is local and the database is public.
 * The tool image must be pinned (`aquasec/trivy:0.76.2`), like every other image.
 *
 * Exit codes: 0 = no HIGH/CRITICAL vulnerability; anything else = findings or a
 * scan error -> the step fails, the report is echoed and archived first.
 *
 * Exceptions: documented in the ignore file of the project (the same
 * `.trivyignore.yaml` used by the IaC scan, section `vulnerabilities:`). The
 * file is passed with `--ignorefile` only when it exists, so the repository does
 * not need it until there is a real exception.
 *
 * Usage:
 *   trivyImageScan(ref: 'localhost:8082/circleguard/auth-service:1.2.0-build.42.ab12cd3',
 *                  toolImage: 'aquasec/trivy:0.76.2',
 *                  severity: 'HIGH,CRITICAL',
 *                  ignoreFile: '.trivyignore.yaml')
 *
 * Returns [ref: ..., report: ..., status: ...].
 * Raises `error` when vulnerabilities are found or the scan fails.
 */
def call(Map params = [:]) {
    String ref = params.ref
    String toolImage = params.toolImage ?: 'aquasec/trivy:0.76.2'
    String severity = params.severity ?: 'HIGH,CRITICAL'
    int timeoutMinutes = params.timeout ?: 15
    String ignoreFile = params.ignoreFile ?: '.trivyignore.yaml'
    String cacheDir = params.cacheDir ?: '/ws/.trivy-cache'
    String volume = params.volume ?: 'circleguard-jenkins-home'

    if (!ref) {
        error 'trivyImageScan: ref is required'
    }
    if (!env.WORKSPACE) {
        error 'trivyImageScan: no workspace available'
    }
    // ref, severity, cache and ignore file are interpolated into a shell command:
    // only image-reference characters are accepted (no spaces, no metacharacters).
    if (!(ref ==~ /[A-Za-z0-9._:\/-]+/)) {
        error "trivyImageScan: invalid image reference: ${ref}"
    }
    if (!(severity ==~ /[A-Za-z0-9,]+/)) {
        error "trivyImageScan: invalid severity: ${severity}"
    }
    if (!(cacheDir ==~ /\/ws\/[A-Za-z0-9._-]+/)) {
        error "trivyImageScan: the cache must live inside /ws: ${cacheDir}"
    }
    if (ignoreFile && !(ignoreFile ==~ /[A-Za-z0-9._-]+/)) {
        error "trivyImageScan: ignoreFile must be a plain file name: ${ignoreFile}"
    }
    // The tool image must carry a concrete tag, never :latest.
    String lastSegment = toolImage.tokenize('/').last()
    if (!lastSegment.contains(':') || lastSegment.endsWith(':latest')) {
        error 'trivyImageScan: the image must be pinned to an explicit version ' +
              "(never latest): ${toolImage}"
    }

    // Only the workspace of this job is mounted (same guard as runInContainer),
    // otherwise the subpath could point at secrets/ or another job's workspace.
    String subPath = env.WORKSPACE.replaceFirst('^/var/jenkins_home/', '')
    if (subPath == env.WORKSPACE || !subPath.startsWith('workspace/')) {
        error "trivyImageScan: workspace is not under /var/jenkins_home/workspace: ${env.WORKSPACE}"
    }
    // volume-subpath requires the directory to exist before mounting it.
    if (!fileExists(env.WORKSPACE)) {
        error "trivyImageScan: workspace ${env.WORKSPACE} does not exist yet " +
              '(Checkout must run before this step)'
    }

    // Unique per build AND per image: a report of a previous build can never be
    // archived as evidence of this one.
    String build = env.BUILD_NUMBER ?: 'nobuild'
    String slug = ref.replaceAll('[^A-Za-z0-9]+', '-').replaceAll('(^-+|-+$)', '')
    String report = "trivy-image-report-${build}-${slug}.txt"

    // The report of a previous run is removed first: a stale file must never be
    // echoed or archived as the evidence of this scan.
    sh "rm -f \"${report}\""

    String ignore = (ignoreFile && fileExists(ignoreFile)) ? " --ignorefile ${ignoreFile}" : ''
    String mountSpec = "type=volume,source=${volume},destination=/ws,volume-subpath=${subPath}"
    // Single source of truth for the socket: the bind mount and the group lookup
    // below must always refer to the same file.
    String socketPath = '/var/run/docker.sock'
    String socketSpec = "type=bind,source=${socketPath},destination=${socketPath}"

    // The container runs with the uid/gid of the agent (`--user`), which is NOT
    // the group that owns the socket: `--user <uid>:<gid>` sets a single numeric
    // group and Docker cannot resolve supplementary groups for an unknown uid.
    // The GID of the socket is read on the host at run time (never assumed: it
    // differs per installation) and passed with --group-add. The shell expands
    // $(stat …) BEFORE docker run: if the GID cannot be read the arguments are
    // malformed, docker run fails and the step fails closed instead of scanning
    // without the supplementary group.
    String command = "docker run --rm --user \$(id -u):\$(id -g) " +
                     "--group-add \$(stat -c '%g' ${socketPath}) -e HOME=/tmp " +
                     "--mount '${mountSpec}' --mount '${socketSpec}' " +
                     "-w /ws ${toolImage} image " +
                     "--severity ${severity} --exit-code 1 --image-src docker " +
                     "--format table --output ${report} --cache-dir ${cacheDir} --quiet" +
                     ignore + " ${ref}"

    echo "Trivy image scan of ${ref} with ${toolImage} (severity ${severity})"

    // The status is captured inside the block: the step never depends on the
    // value returned by `timeout`.
    int status = -1
    timeout(time: timeoutMinutes, unit: 'MINUTES') {
        status = sh(script: command, returnStatus: true)
    }

    // The report is written even when the exit code is 1 (findings), so it is
    // echoed and archived BEFORE the step fails.
    boolean reported = fileExists(report)
    if (reported) {
        echo readFile(report)
        archiveArtifacts artifacts: report, allowEmptyArchive: true
    }

    if (status == 0) {
        echo "trivyImageScan: no ${severity} vulnerabilities in ${ref}"
    } else if (reported) {
        error "trivyImageScan: ${severity} vulnerabilities in ${ref} (exit ${status}). " +
              "Fix them or document the exception in ${ignoreFile}. " +
              "Report archived: ${report}."
    } else {
        error "trivyImageScan: the scan of ${ref} failed (exit ${status}) and no report " +
              'was generated, see the container output above.'
    }

    return [ref: ref, report: report, status: status]
}
