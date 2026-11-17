/**
 * Scans the Terraform code with Trivy (`trivy config`) and BLOCKS the build when
 * a misconfiguration of severity HIGH or CRITICAL is found.
 *
 * `trivy config` only runs the misconfiguration scanner (HCL/CloudFormation/...),
 * so it never prints secrets and never needs network credentials. The state files
 * and the saved plans are excluded explicitly because they can contain sensitive
 * values and are not configuration to review.
 *
 * Cache (H2): the Trivy cache lives INSIDE the workspace of the job
 * (`/ws/.trivy-cache`), so every job has its own bbolt database and two
 * concurrent builds can never share it (Trivy fails with "cache may be in use by
 * another process" when another process holds the lock). It is created by the
 * non-root user of the container (`--user` = owner of the workspace) and lives
 * in the same mount as the code, so it is also excluded from the scan.
 *
 * Report (H4/H5): the report name includes the build number, so the report of a
 * previous build can never be archived as evidence of the current one. The
 * report is echoed and archived BEFORE the step fails, and the error message
 * distinguishes the case where Trivy did not write any report.
 *
 * Exceptions: a justified finding must NOT disable the scan globally. Create
 * `.trivyignore.yaml` in the workspace root with the specific check id and a
 * comment explaining why (e.g. `AVD-AWS-0123: accepted risk, documented in HU2`);
 * the file is passed to Trivy with `--ignorefile` only when it exists.
 *
 * Usage:
 *   trivyScan()                                            // defaults
 *   trivyScan(paths: ['infra/terraform'],
 *             severity: 'HIGH,CRITICAL',
 *             image: 'aquasec/trivy:0.76.2')
 *
 * Returns nothing; raises `error` when findings (or a scan error) are reported.
 */
def call(Map params = [:]) {
    String image = params.image ?: 'aquasec/trivy:0.76.2'
    List<String> paths = params.paths ?: []
    String severity = params.severity ?: 'HIGH,CRITICAL'
    String ignoreFile = params.ignoreFile ?: '.trivyignore.yaml'
    // Inside the mount of the workspace (see runInContainer): persistent for the
    // jobs that keep their workspace and, above all, NEVER shared between jobs.
    String cacheDir = params.cacheDir ?: '/ws/.trivy-cache'
    int timeoutMinutes = params.timeout ?: 15

    if (!paths) {
        error 'trivyScan: paths are required'
    }
    if (!env.WORKSPACE) {
        error 'trivyScan: no workspace available'
    }

    // `trivy config` accepts exactly ONE target per invocation, so the scan runs
    // once per path. Trivy resolves `--skip-*` with glob patterns, hence both the
    // plain and the `**/` form of every exclusion.
    String exclusions = ' --skip-dirs .git --skip-dirs .terraform' +
                        ' --skip-dirs "**/.terraform"' +
                        ' --skip-dirs .trivy-cache' +
                        ' --skip-dirs "**/.trivy-cache"' +
                        " --skip-files '*.tfstate*'" +
                        " --skip-files '**/*.tfstate*'" +
                        " --skip-files '*.tfplan*'" +
                        " --skip-files '**/*.tfplan*'"
    String ignore = (ignoreFile && fileExists(ignoreFile)) ? " --ignorefile ${ignoreFile}" : ''

    // Unique per build: a report left by a previous build has a different name
    // and can never be archived as evidence of this one (H4).
    String build = env.BUILD_NUMBER ?: 'nobuild'
    String reportPrefix = "trivy-iac-report-${build}"

    echo "Trivy IaC misconfigurations with ${image} (severity ${severity})"

    int failedPaths = 0
    List<String> failed = []
    List<String> reports = []      // report of this build, archived
    List<String> withoutReport = [] // target without report (scan error before writing)

    for (String path : paths) {
        if (!fileExists(path)) {
            error "trivyScan: ${path} does not exist in the workspace"
        }

        String slug = paths.size() == 1 ? '' :
            '-' + path.replaceAll('[^A-Za-z0-9]+', '-').replaceAll('(^-+|-+$)', '')
        String report = "${reportPrefix}${slug}.txt"

        String command = "config ${path}" +
                         " --severity ${severity}" +
                         ' --exit-code 1' +
                         " --format table --output ${report} --quiet" +
                         " --cache-dir ${cacheDir}" +
                         exclusions + ignore

        int status = runInContainer(image: image,
                                    command: command,
                                    timeout: timeoutMinutes,
                                    returnStatus: true)

        // The report is written even when the exit code is 1 (findings).
        if (fileExists(report)) {
            echo readFile(report)
            archiveArtifacts artifacts: report, allowEmptyArchive: true
            reports << report
        } else {
            withoutReport << path
        }

        if (status != 0) {
            failedPaths++
            failed << path
            echo "trivyScan: findings or scan error in ${path} (exit ${status}) -> ${report}"
        }
    }

    if (failedPaths) {
        // H5: only point to the archived report when it really exists.
        String evidence
        if (reports) {
            evidence = "Report(s) archived: ${reports.join(', ')}."
            if (withoutReport) {
                evidence += " No report was generated for: ${withoutReport.join(', ')}."
            }
        } else {
            evidence = 'No report was generated, see the container output above.'
        }
        error "trivyScan: HIGH/CRITICAL misconfigurations (severity ${severity}) in: " +
              "${failed.join(', ')}. Fix them or document the exception in " +
              ".trivyignore.yaml. ${evidence}"
    }

    echo "trivyScan: no HIGH/CRITICAL misconfigurations in ${paths.join(', ')}"
}
