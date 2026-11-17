/**
 * Runs a command inside a container with access to the JOB WORKSPACE ONLY.
 *
 * Jenkins runs in its own container and talks to the Docker daemon of the host
 * through /var/run/docker.sock, so the daemon resolves HOST paths: the workspace
 * cannot be mounted with `-v $WORKSPACE:...`.
 *
 * Isolation (H1): instead of exposing the whole `circleguard-jenkins-home` volume
 * (which contains credentials.xml, secrets/ and the workspaces of every other
 * job), only the subdirectory of the current job is mounted, using the
 * `volume-subpath` option of `--mount`:
 *
 *   --mount type=volume,source=circleguard-jenkins-home,destination=/ws,\
 *          volume-subpath=workspace/circleguard_dev
 *
 * The mount point inside the container is `/ws`, so the workspace root is `/ws`
 * and every repository-relative path (e.g. `infra/terraform`) is resolved from
 * there. Steps that need a path inside the workspace (Trivy cache, Terraform
 * plugin cache) must use `/ws/...`.
 *
 * Two guards run before the mount:
 *   - the workspace must live under /var/jenkins_home/workspace (otherwise the
 *     subpath would point outside the workspace, e.g. at secrets/);
 *   - the subdirectory must already exist: `volume-subpath` fails when it does
 *     not, and it is created by the Checkout stage, which always runs first.
 *
 * ⚠ volume-subpath is documented by the Docker Engine and supported by the
 * Docker 29.9.3 of the host, BUT it has not been executed yet in this
 * environment: it must be confirmed with a real `docker run` before considering
 * it validated. Fallback if the mount fails: mount the whole volume with
 * `-v circleguard-jenkins-home:/jh` and translate `/var/jenkins_home/...` to
 * `/jh/...` (the behaviour used until Fase 1.1 and still used by runE2E).
 *
 * The container runs with the uid/gid of the workspace owner and HOME=/tmp, so
 * the files it writes (reports, .terraform/, ...) are not root-owned and the
 * next checkout can clean them up.
 *
 * The image MUST be pinned to an explicit version: `:latest` and untagged images
 * are rejected, like publishImages does with the image tags.
 *
 * Environment variables are passed BY NAME (`envVars: ['AWS_REGION']`), so their
 * values never appear in the command line or in the build log; they are only
 * visible to the process when the caller wraps the step in withCredentials().
 *
 * Usage:
 *   runInContainer(image: 'hashicorp/terraform:1.17.2',
 *                  command: 'fmt -check -recursive -no-color infra/terraform')
 *
 *   int status = runInContainer(image: 'aquasec/trivy:0.76.2',
 *                               command: 'config infra/terraform --exit-code 1',
 *                               returnStatus: true)
 *
 * Returns null, or the exit status of the command when `returnStatus: true`.
 */
def call(Map params = [:]) {
    String image = params.image
    String command = params.command
    String workDir = params.workDir ?: '.'
    List<String> envVars = params.envVars ?: []
    String volume = params.volume ?: 'circleguard-jenkins-home'
    String mountPoint = params.mountPoint ?: '/ws'
    String home = params.home ?: '/tmp'
    int timeoutMinutes = params.timeout ?: 10
    boolean returnStatus = params.returnStatus ?: false

    if (!image) {
        error 'runInContainer: image is required'
    }
    if (!command) {
        error 'runInContainer: command is required'
    }

    // The last segment must carry a concrete tag: "registry:5000/img" is not enough.
    String lastSegment = image.tokenize('/').last()
    if (!lastSegment.contains(':') || lastSegment.endsWith(':latest')) {
        error "runInContainer: the image must be pinned to an explicit version (never latest): ${image}"
    }

    if (!env.WORKSPACE) {
        error 'runInContainer: no workspace available'
    }

    // Path of the job workspace inside the volume: workspace/<job>.
    String subPath = env.WORKSPACE.replaceFirst('^/var/jenkins_home/', '')
    if (subPath == env.WORKSPACE || !subPath.startsWith('workspace/')) {
        error "runInContainer: workspace is not under /var/jenkins_home/workspace: ${env.WORKSPACE}"
    }
    // volume-subpath requires the directory to exist before mounting it.
    if (!fileExists(env.WORKSPACE)) {
        error "runInContainer: workspace ${env.WORKSPACE} does not exist yet (Checkout must run before this step)"
    }

    String dir = (workDir in ['', '.']) ? mountPoint : "${mountPoint}/${workDir}"
    // `--mount` must stay OUTSIDE the quotes together with its value: quoting the
    // flag and the value as one word would make the shell pass
    // "--mount type=volume,..." as a single argument, and the Docker CLI would
    // parse the flag name as "mount type" -> `unknown flag: --mount type`.
    String mountSpec = "type=volume,source=${volume},destination=${mountPoint},volume-subpath=${subPath}"
    String envArgs = envVars.collect { "-e ${it}" }.join(' ')

    String script = "docker run --rm --user \$(id -u):\$(id -g) -e HOME=${home} " +
                    "--mount '${mountSpec}' -w '${dir}' ${envArgs} ${image} ${command}"

    echo "runInContainer: ${image} :: ${command}"

    return timeout(time: timeoutMinutes, unit: 'MINUTES') {
        if (returnStatus) {
            return sh(script: script, returnStatus: true)
        }
        sh script
        return null
    }
}
