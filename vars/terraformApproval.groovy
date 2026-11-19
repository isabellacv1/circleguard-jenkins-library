/**
 * Asks for a MANUAL approval before a Terraform apply (E4, S3).
 *
 * This step is standalone: it is NOT wired into circleguardPipeline yet, and it
 * runs NO Terraform and NO AWS command. The only command it executes is a local
 * `sha256sum` to prove that the plan file still has the hash that the plan stage
 * recorded.
 *
 * Everything is verified BEFORE the `input` is shown, so a build never waits for
 * an approval of a plan that cannot be applied:
 *
 *   1. root guards (relative path, exists) and sane timeout/maxAge/submitter
 *   2. env.TF_PLAN_BUILD exists and equals env.BUILD_NUMBER
 *   3. env.TF_PLAN_ROOT, TF_PLAN_FILE and TF_PLAN_INFO match this target
 *   4. env.TF_PLAN_CHANGES is 'true' (a clean plan has nothing to approve)
 *   5. env.TF_PLAN_SHA256 and env.GIT_COMMIT exist
 *   6. the plan file and its `<plan>.info` sidecar exist
 *   7. the sidecar matches build, commit and root of THIS build, with
 *      changes='true' and a well formed sha256
 *   8. the sidecar sha256 equals env.TF_PLAN_SHA256
 *   9. the sha256 recomputed with `sha256sum` equals the sidecar (fail closed
 *      when the tool is missing: nothing is asked)
 *  10. `createdAt` is a valid instant, not in the future, and the plan is not
 *      older than maxAgeMinutes (default 60)
 *
 * The approval is requested with:
 *
 *   input(message: <build, commit, root, sha256, changes and age>,
 *         ok: 'Approve terraform apply',
 *         submitter: <terraformApprovalSubmitter, default 'admin'>,
 *         submitterParameter: 'approvedBy',
 *         timeout: <terraformApprovalTimeout, default 30>,
 *         timeUnit: 'MINUTES')
 *
 * A timeout or a manual cancel surfaces as FlowInterruptedException: it is
 * caught ONLY to echo that the approval did not happen and that NO
 * infrastructure was changed, and the ORIGINAL exception is rethrown
 * (`throw e`), so Jenkins keeps marking the build as aborted/timed out.
 *
 * After a valid approval the step persists:
 *
 *   env.TF_APPROVED_BY, env.TF_APPROVED_AT, env.TF_APPROVED_PLAN_SHA,
 *   env.TF_APPROVED_BUILD
 *
 * and refuses to continue when the approval carries no valid identity.
 *
 * Usage (not called by the pipeline yet):
 *   terraformApproval(root: 'infra/terraform/envs/prod',
 *                     submitter: 'admin',
 *                     timeout: 30,
 *                     maxAgeMinutes: 60)
 *
 * Returns [approvedBy: ..., approvedAt: ..., sha256: ..., build: ...].
 */
def call(Map params = [:]) {
    String root = params.root
    int timeoutMinutes = params.timeout ?: 30
    String submitter = params.submitter ?: 'admin'
    int maxAgeMinutes = params.maxAgeMinutes ?: 60
    String planFile = params.planFile

    // ---------------------------------------------------------------- guards
    if (!root) {
        error 'terraformApproval: root is required'
    }
    if (!env.WORKSPACE) {
        error 'terraformApproval: no workspace available'
    }
    if (timeoutMinutes <= 0) {
        error "terraformApproval: timeout must be > 0 minutes, got ${timeoutMinutes}"
    }
    if (maxAgeMinutes <= 0) {
        error "terraformApproval: maxAgeMinutes must be > 0 minutes, got ${maxAgeMinutes}"
    }
    if (!submitter || !submitter.trim()) {
        error 'terraformApproval: submitter is required (who is allowed to approve)'
    }
    // The root and the file names are only read (never mounted), but they are
    // interpolated into a command: accept relative paths without `..`.
    if (root.startsWith('/') || root.split('/').contains('..') || !(root ==~ /[A-Za-z0-9._\/-]+/)) {
        error "terraformApproval: root must be a relative path inside the workspace " +
              "without '..': ${root}"
    }
    if (!fileExists(root)) {
        error "terraformApproval: root ${root} does not exist in the workspace"
    }

    String build = env.BUILD_NUMBER ?: 'nobuild'
    // Same formula as terraformPlan/terraformApply: ci-<env>-b<build>.tfplan
    if (!planFile) {
        planFile = "ci-${root.tokenize('/').last()}-b${build}.tfplan"
    }
    if (!(planFile ==~ /[A-Za-z0-9._-]+/) || !planFile.endsWith('.tfplan')) {
        error "terraformApproval: planFile must be a plain name ending in .tfplan: ${planFile}"
    }
    String planPath = "${root}/${planFile}"
    String infoPath = "${planPath}.info"

    // ------------------------------------------------- identity of the plan
    if (!env.TF_PLAN_BUILD) {
        error 'terraformApproval: no plan was produced in this build ' +
              '(TF_PLAN_BUILD is not set): run the Terraform plan stage first'
    }
    if (env.TF_PLAN_BUILD != build) {
        error "terraformApproval: the plan belongs to build ${env.TF_PLAN_BUILD}, " +
              "this is build ${build}: refusing to approve a plan of another build"
    }
    if (env.TF_PLAN_ROOT != root) {
        error "terraformApproval: the plan was produced for ${env.TF_PLAN_ROOT} " +
              "but this target is ${root}: refusing to approve the wrong plan"
    }
    if (env.TF_PLAN_FILE != planPath) {
        error "terraformApproval: expected plan ${planPath} but the plan stage " +
              "produced ${env.TF_PLAN_FILE}: refusing to approve"
    }
    if (env.TF_PLAN_INFO != infoPath) {
        error "terraformApproval: expected sidecar ${infoPath} but the plan stage " +
              "produced ${env.TF_PLAN_INFO}: refusing to approve"
    }
    if (env.TF_PLAN_CHANGES != 'true') {
        error "terraformApproval: the plan of ${root} has no changes " +
              "(TF_PLAN_CHANGES=${env.TF_PLAN_CHANGES}): there is nothing to approve"
    }
    if (!env.TF_PLAN_SHA256) {
        error 'terraformApproval: TF_PLAN_SHA256 is not set: the plan stage must ' +
              'publish it before an approval is requested'
    }
    if (!env.GIT_COMMIT) {
        error 'terraformApproval: GIT_COMMIT is not available, the plan provenance ' +
              'cannot be verified'
    }
    if (!fileExists(planPath)) {
        error "terraformApproval: the plan ${planPath} does not exist in the workspace"
    }
    if (!fileExists(infoPath)) {
        error "terraformApproval: the sidecar ${infoPath} does not exist in the workspace"
    }

    // Sidecar written by terraformPlan: build, commit, root, changes, status,
    // sha256, createdAt. Every field is compared, not just its presence.
    Map info = [:]
    for (String line : readFile(infoPath).readLines()) {
        String trimmed = line.trim()
        int idx = trimmed.indexOf('=')
        if (trimmed && idx > 0) {
            info[trimmed.substring(0, idx)] = trimmed.substring(idx + 1)
        }
    }
    if (info.build != build) {
        error "terraformApproval: the sidecar says build=${info.build}, this is build ${build}"
    }
    if (info.commit != env.GIT_COMMIT) {
        error "terraformApproval: the sidecar says commit=${info.commit} but this build " +
              "is commit ${env.GIT_COMMIT}: the plan belongs to another revision"
    }
    if (info.root != root) {
        error "terraformApproval: the sidecar says root=${info.root}, expected ${root}"
    }
    if (info.changes != 'true') {
        error "terraformApproval: the sidecar says changes=${info.changes}: " +
              'there is nothing to approve'
    }
    if (!(info.sha256 ==~ /[0-9a-f]{64}/)) {
        error "terraformApproval: the sidecar has no valid sha256 for the plan " +
              "('${info.sha256}'): refusing to ask for an approval"
    }
    if (info.sha256 != env.TF_PLAN_SHA256) {
        error "terraformApproval: the sidecar says sha256=${info.sha256} but the plan " +
              "stage published ${env.TF_PLAN_SHA256}: inconsistent plan state"
    }

    // Recomputed hash (fail closed): the approval must bind to the file that is
    // really in the workspace right now.
    String planHash = ''
    try {
        String output = sh(script: "sha256sum \"${planPath}\"", returnStdout: true)
        planHash = output.trim().split(/\s+/)[0] ?: ''
    } catch (Exception e) {
        error "terraformApproval: unable to compute the SHA-256 of ${planPath} " +
              "(${e.message}): sha256sum is required to prove the plan, refusing to " +
              'ask for an approval'
    }
    if (planHash != info.sha256) {
        error "terraformApproval: the SHA-256 of ${planPath} is ${planHash} but the " +
              "sidecar records ${info.sha256}: the plan changed after it was produced"
    }

    // Freshness of the plan.
    java.time.Instant created
    try {
        created = java.time.Instant.parse(info.createdAt)
    } catch (Exception e) {
        error "terraformApproval: the sidecar has an invalid createdAt " +
              "('${info.createdAt}'): refusing to ask for an approval"
    }
    long ageMinutes = java.time.Duration.between(created, java.time.Instant.now()).toMinutes()
    if (ageMinutes < 0) {
        error "terraformApproval: the plan is dated in the future " +
              "(${info.createdAt}): refusing to ask for an approval"
    }
    if (ageMinutes > maxAgeMinutes) {
        error "terraformApproval: the plan is ${ageMinutes} minutes old, more than the " +
              "maximum of ${maxAgeMinutes}: it must be regenerated, request a new build"
    }

    // ------------------------------------------------------------- approval
    String message = """Terraform apply approval
=========================
Root      : ${root}
Build     : ${build}
Commit    : ${env.GIT_COMMIT}
Plan      : ${planPath}
SHA-256   : ${info.sha256}
Changes   : yes (this plan modifies the infrastructure)
Plan age  : ${ageMinutes} min (maximum ${maxAgeMinutes} min)

The plan is printed in the console of the 'Terraform plan' stage.
Approving lets the 'Terraform apply' stage run in THIS build (${build})."""

    Object answer
    try {
        answer = input(message: message,
                       ok: 'Approve terraform apply',
                       submitter: submitter,
                       submitterParameter: 'approvedBy',
                       timeout: timeoutMinutes,
                       timeUnit: 'MINUTES')
    } catch (Exception e) {
        // Only to explain what happened: the original exception is rethrown so
        // Jenkins still marks the build as aborted/timed out.
        if (e.getClass().name.contains('FlowInterruptedException')) {
            echo "terraformApproval: the approval for ${root} was ${interruptionDetail(e)}: " +
                 'NO infrastructure was changed. Request a new build to approve a fresh plan.'
        }
        throw e
    }

    // The approval must carry a real identity (submitterParameter/parameters).
    String approvedBy = (answer instanceof Map) ? answer.approvedBy?.toString()
                                                : answer?.toString()
    if (!approvedBy || !approvedBy.trim() || approvedBy == 'null') {
        error 'terraformApproval: the approval carries no valid identity ' +
              '(approvedBy): refusing to continue'
    }

    String approvedAt = java.time.Instant.now().toString()
    env.TF_APPROVED_BY = approvedBy
    env.TF_APPROVED_AT = approvedAt
    env.TF_APPROVED_PLAN_SHA = info.sha256
    env.TF_APPROVED_BUILD = build

    echo "terraformApproval: approved by ${approvedBy} at ${approvedAt} for " +
         "${planPath} (sha256 ${info.sha256}, build ${build})"

    return [approvedBy: approvedBy,
            approvedAt: approvedAt,
            sha256    : info.sha256,
            build     : build]
}

/**
 * Best effort classification of an interrupted `input`: the real Jenkins classes
 * are detected by name (they must not be imported, or the local tests could not
 * compile). Falls back to the generic wording when the shape is unknown.
 */
String interruptionDetail(Exception e) {
    try {
        if (e.hasProperty('causes')) {
            def causes = e.causes
            if (causes) {
                String names = causes.collect { it.getClass().name }.join(',')
                if (names.contains('ExceededTimeout')) {
                    return 'expired (timeout)'
                }
                return 'cancelled'
            }
        }
    } catch (Exception ignored) {
        // unexpected shape: keep the generic wording below
    }
    return 'expired or cancelled'
}
