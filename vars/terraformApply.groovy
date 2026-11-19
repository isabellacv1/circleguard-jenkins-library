/**
 * Applies the plan produced by `terraformPlan` IN THE SAME BUILD (DEV only in
 * this phase: STAGE and PROD are not enabled yet).
 *
 * Nothing runs before the provenance of the plan is verified. All checks fail
 * with `error` BEFORE any Terraform command, so an inconsistent plan is never
 * applied:
 *
 *   1. root/workspace/versions.tf guards (same as terraformPlan)
 *   2. env.TF_PLAN_BUILD exists and equals env.BUILD_NUMBER  (plan of THIS build)
 *   3. env.TF_PLAN_ROOT equals the root of this target
 *   4. env.TF_PLAN_FILE equals the recomputed `ci-<env>-b<build>.tfplan`
 *   5. env.TF_PLAN_INFO  equals `<plan>.info`
 *   6. env.TF_PLAN_CHANGES is 'true' or 'false' and matches the sidecar
 *   7. env.GIT_COMMIT exists and matches the sidecar (commit of the plan)
 *   8. the plan file and the `<plan>.info` sidecar exist
 *   9. the `<plan>.applied` marker does NOT exist (never apply twice)
 *
 * When the target requires an approval (`requireApproval: true`, the PROD
 * switch wired by the pipeline in a later step), ALL of these are also verified
 * BEFORE `withCredentials`, `terraform init` and `terraform apply`:
 *
 *  10. TF_APPROVED_BY / TF_APPROVED_AT / TF_APPROVED_PLAN_SHA /
 *      TF_APPROVED_BUILD exist, the approver is not empty and the approval date
 *      is valid and not in the future
 *  11. TF_APPROVED_BUILD equals BUILD_NUMBER, and TF_APPROVED_PLAN_SHA equals
 *      TF_PLAN_SHA256, which equals the sidecar sha256, which equals the
 *      sha256 recomputed from the plan file
 *  12. the plan still has changes, its `createdAt` is valid, not in the future
 *      and not older than `maxAgeMinutes` (default 60 =
 *      terraformApprovalMaxAgeMinutes), and the approval itself is not older
 *      than that same window
 *
 * DEV never sets `requireApproval`, so its behaviour is byte for byte the same.
 *
 * When the plan reported no changes the step registers `SKIPPED_NO_CHANGES` and
 * omits init and apply entirely (no AWS call, no lock).
 *
 * With changes, it runs (inside `withCredentials`, values passed BY NAME):
 *
 *   terraform init  -backend=true -no-color -input=false
 *   terraform apply -no-color -input=false -lock=true <ci-<env>-b<build>.tfplan>
 *
 * Never uses `-lock=false`, `-auto-approve`, `-destroy`, `-replace` or any other
 * destructive flag: only the reviewed plan of this build is applied, exactly as
 * `docs/operaciones/terraform.md` §5 requires.
 *
 * After a SUCCESSFUL apply, and in this order (no automatic retries anywhere):
 *
 *   1. `<plan>.applied` marker   (blocks a second apply of the same plan)
 *   2. `terraform-apply-<env>-b<build>.txt` evidence, archived
 *      (build, branch, commit, root, plan, changes, outcome, date: NO credentials
 *       and NO outputs are written or echoed)
 *   3. `rm` of the plan and its sidecar
 *
 * If step 2 or 3 fails, the step reports explicitly that the apply SUCCEEDED and
 * that the build must NOT be re-run blindly (the marker, written first, keeps a
 * re-run from applying again).
 *
 * On failure of `init`/`apply` the original exception is rethrown unchanged
 * (`throw e`); the AccessDenied guidance is echoed ONLY when the failure really
 * is an AccessDenied (never for an interruption): the IAM policies are never
 * widened from a build failure.
 *
 * Concurrency: `circleguardPipeline` uses `disableConcurrentBuilds()` (without
 * `abortPrevious`), so a newer build of the same branch QUEUES instead of
 * aborting this one: an apply in progress is never cancelled by a new push.
 * Other interruptions (stage timeout, manual abort) can still stop it; see the
 * README section "Concurrency: builds queue" for the recovery runbook.
 *
 * Usage:
 *   terraformApply(root: 'infra/terraform/envs/dev',
 *                  credentialsId: 'aws-terraform-credentials',
 *                  image: 'hashicorp/terraform:1.17.2',
 *                  region: 'us-east-1',
 *                  timeout: 30)
 *
 * Returns [root: ..., planFile: ..., status: 'APPLIED' | 'SKIPPED_NO_CHANGES'].
 */
def call(Map params = [:]) {
    String image = params.image ?: 'hashicorp/terraform:1.17.2'
    String root = params.root
    // containsKey: an explicitly empty/null credential id must FAIL instead of
    // silently falling back to the default (an apply must never run anonymously).
    String credentialsId = params.containsKey('credentialsId') ? params.credentialsId
                                                              : 'aws-terraform-credentials'
    String region = params.region ?: 'us-east-1'
    int timeoutMinutes = params.timeout ?: 30
    int minFreeSpaceMB = params.minFreeSpaceMB ?: 1500
    String pluginCacheName = params.pluginCacheDir ?: '.terraform-plugin-cache'
    String planFile = params.planFile
    // Approval gate (E4, S4). DEV never sets it, so its behaviour is unchanged;
    // a target that requires an approval (PROD, wired in a later step) must have
    // a valid approval of THIS plan before anything talks to AWS.
    boolean requireApproval = params.requireApproval ?: false
    // Validity window of the plan AND of its approval. There is no dedicated
    // setting for it, so this reuses terraformApprovalMaxAgeMinutes (60): one
    // window keeps one rule, and the plan age is always the dominant constraint
    // because an approval is produced after the plan.
    int maxAgeMinutes = params.maxAgeMinutes ?: 60

    // ---------------------------------------------------------------- guards
    if (!root) {
        error 'terraformApply: root is required'
    }
    if (!credentialsId) {
        error 'terraformApply: credentialsId is required'
    }
    if (!env.WORKSPACE) {
        error 'terraformApply: no workspace available'
    }
    // Only the workspace of this job is mounted (same guard as terraformPlan),
    // so the mount can never point at secrets/ or another job's workspace.
    String subPath = env.WORKSPACE.replaceFirst('^/var/jenkins_home/', '')
    if (subPath == env.WORKSPACE || !subPath.startsWith('workspace/')) {
        error "terraformApply: workspace is not under /var/jenkins_home/workspace: ${env.WORKSPACE}"
    }
    // The root and the file names are interpolated into shell commands: only a
    // relative path made of path characters is accepted (no absolute path, no
    // `..`, so nothing can escape the workspace of the job).
    if (root.startsWith('/') || root.split('/').contains('..') || !(root ==~ /[A-Za-z0-9._\/-]+/)) {
        error "terraformApply: root must be a relative path inside the workspace " +
              "without '..': ${root}"
    }
    if (!(pluginCacheName ==~ /[A-Za-z0-9._-]+/)) {
        error "terraformApply: invalid plugin cache directory name: ${pluginCacheName}"
    }
    if (!fileExists(root)) {
        error "terraformApply: root ${root} does not exist in the workspace"
    }
    String versionsFile = "${root}/versions.tf"
    if (!fileExists(versionsFile)) {
        error "terraformApply: ${versionsFile} does not exist in the workspace, " +
              "the backend of ${root} cannot be initialised"
    }

    String build = env.BUILD_NUMBER ?: 'nobuild'
    // Same formula as terraformPlan: ci-<env>-b<build>.tfplan
    if (!planFile) {
        planFile = "ci-${root.tokenize('/').last()}-b${build}.tfplan"
    }
    if (!(planFile ==~ /[A-Za-z0-9._-]+/) || !planFile.endsWith('.tfplan')) {
        error "terraformApply: planFile must be a plain name ending in .tfplan: ${planFile}"
    }
    String planPath = "${root}/${planFile}"
    String infoPath = "${planPath}.info"
    String appliedPath = "${planPath}.applied"

    // ------------------------------------------------- provenance of the plan
    if (!env.TF_PLAN_BUILD) {
        error 'terraformApply: no plan was produced in this build ' +
              '(TF_PLAN_BUILD is not set): run the Terraform plan stage first'
    }
    if (env.TF_PLAN_BUILD != build) {
        error "terraformApply: the plan belongs to build ${env.TF_PLAN_BUILD}, " +
              "this is build ${build}: refusing to apply a plan of another build"
    }
    if (env.TF_PLAN_ROOT != root) {
        error "terraformApply: the plan was produced for ${env.TF_PLAN_ROOT} " +
              "but this target is ${root}: refusing to apply the wrong plan"
    }
    if (env.TF_PLAN_FILE != planPath) {
        error "terraformApply: expected plan ${planPath} but the plan stage " +
              "produced ${env.TF_PLAN_FILE}: refusing to apply"
    }
    if (env.TF_PLAN_INFO != infoPath) {
        error "terraformApply: expected sidecar ${infoPath} but the plan stage " +
              "produced ${env.TF_PLAN_INFO}: refusing to apply"
    }
    String changes = env.TF_PLAN_CHANGES
    if (changes != 'true' && changes != 'false') {
        error "terraformApply: invalid TF_PLAN_CHANGES value '${changes}': refusing to apply"
    }
    if (!env.GIT_COMMIT) {
        error 'terraformApply: GIT_COMMIT is not available, the plan provenance ' +
              'cannot be verified'
    }
    if (!fileExists(planPath)) {
        error "terraformApply: the plan ${planPath} does not exist in the workspace"
    }
    if (!fileExists(infoPath)) {
        error "terraformApply: the sidecar ${infoPath} does not exist in the workspace"
    }
    if (fileExists(appliedPath)) {
        error "terraformApply: ${planPath} was already applied in this workspace " +
              "(${appliedPath}): refusing to apply it twice"
    }

    // Sidecar written by terraformPlan: build, commit, root, changes, status,
    // sha256 and date. Every field is compared, not just its presence.
    Map info = [:]
    for (String line : readFile(infoPath).readLines()) {
        String trimmed = line.trim()
        int idx = trimmed.indexOf('=')
        if (trimmed && idx > 0) {
            info[trimmed.substring(0, idx)] = trimmed.substring(idx + 1)
        }
    }
    if (info.build != build) {
        error "terraformApply: the sidecar says build=${info.build}, this is build ${build}"
    }
    if (info.root != root) {
        error "terraformApply: the sidecar says root=${info.root}, expected ${root}"
    }
    if (info.commit != env.GIT_COMMIT) {
        error "terraformApply: the sidecar says commit=${info.commit} but this build " +
              "is commit ${env.GIT_COMMIT}: the plan belongs to another revision"
    }
    if (info.changes != changes) {
        error "terraformApply: the sidecar says changes=${info.changes} but the plan " +
              "stage reported ${changes}: inconsistent plan state"
    }
    // status is written together with changes (2 -> changes, 0 -> none): a
    // mismatch means the sidecar does not describe this plan.
    String expectedStatus = (changes == 'true') ? '2' : '0'
    if (info.status != expectedStatus) {
        error "terraformApply: the sidecar says status=${info.status} but changes=" +
              "${changes} (expected status=${expectedStatus}): inconsistent plan state"
    }
    // The plan hash must be a real SHA-256: without it the content of the plan
    // cannot be verified in the next check.
    if (!(info.sha256 ==~ /[0-9a-f]{64}/)) {
        error "terraformApply: the sidecar has no valid sha256 for the plan " +
              "('${info.sha256}'): refusing to apply"
    }

    // Approval gate, part 1: an approval-gated target must have something to
    // approve. It runs BEFORE the SKIPPED path below, which stays untouched for
    // DEV (a target without approval and without changes still skips cleanly).
    if (requireApproval && changes != 'true') {
        error "terraformApply: the plan of ${root} has no changes: " +
              'there is nothing to approve'
    }

    String envName = root.tokenize('/').last()
    String evidence = "${root}/terraform-apply-${envName}-b${build}.txt"
    // java.time instead of Date.format(String, TimeZone): available in every
    // Groovy version (the DGM overload is not) and always UTC.
    String createdAt = java.time.Instant.now().toString()

    String outcome = 'APPLIED'
    if (changes == 'false') {
        // Nothing to apply: no AWS call, no lock, no init, no apply.
        outcome = 'SKIPPED_NO_CHANGES'
        echo "terraformApply: SKIPPED_NO_CHANGES for ${root} (the plan of build " +
             "${build} has no changes)"
        writeEvidence(evidence, build, root, planPath, changes, outcome, createdAt)
        return [root: root, planFile: planPath, status: outcome]
    }

    // ------------------------------------------------------------- disk/cache
    String df = sh(script: "df -Pk \"${env.WORKSPACE}\"", returnStdout: true)
    long availableMB = terraformValidate.freeSpaceMB(df)
    if (availableMB < 0) {
        error 'terraformApply: unable to read the free space of the workspace'
    }
    if (availableMB < minFreeSpaceMB) {
        error "terraformApply: ${availableMB} MB free in the workspace, " +
              "${minFreeSpaceMB} MB required (Terraform downloads ~772 MB of providers). " +
              'Aborting before running Terraform: nothing was applied.'
    }
    echo "terraformApply: ${availableMB} MB available (minimum ${minFreeSpaceMB} MB)"

    // SHA-256: recomputed here and compared with the sidecar written by
    // terraformPlan, so a plan modified after it was produced is never applied.
    // Fail CLOSED when sha256sum is missing: without it nothing is verified.
    String planHash = ''
    try {
        String output = sh(script: "sha256sum \"${planPath}\"", returnStdout: true)
        planHash = output.trim().split(/\s+/)[0] ?: ''
    } catch (Exception e) {
        error "terraformApply: unable to compute the SHA-256 of ${planPath} " +
              "(${e.message}): sha256sum is required to verify the plan, " +
              'refusing to apply'
    }
    if (planHash != info.sha256) {
        error "terraformApply: the SHA-256 of ${planPath} is ${planHash} but the " +
              "sidecar records ${info.sha256}: the plan changed after it was produced"
    }
    echo "terraformApply: plan hash verified (${planHash})"

    // Approval gate, part 2: every value the approval must match, checked AFTER
    // the plan hash and BEFORE mkdir, withCredentials, init and apply.
    Map approval = null
    if (requireApproval) {
        long planAge = checkApproval(build, root, info, planHash, maxAgeMinutes)
        approval = [approvedBy  : env.TF_APPROVED_BY,
                    approvedAt  : env.TF_APPROVED_AT,
                    approvedSha : env.TF_APPROVED_PLAN_SHA,
                    approvedBuild: env.TF_APPROVED_BUILD,
                    planAge     : planAge]
        echo "terraformApply: approval verified (by ${env.TF_APPROVED_BY}, " +
             "build ${env.TF_APPROVED_BUILD}, plan age ${planAge} min)"
    }

    sh "mkdir -p \"${env.WORKSPACE}/${pluginCacheName}\""
    String pluginCache = "/ws/${pluginCacheName}"

    echo "terraform apply of ${root} with ${image} (${planPath})"

    // Credentials only around the commands that talk to AWS. Values are passed
    // BY NAME to runInContainer: they never reach a command line or the log.
    withCredentials([usernamePassword(credentialsId: credentialsId,
                                      usernameVariable: 'AWS_ACCESS_KEY_ID',
                                      passwordVariable: 'AWS_SECRET_ACCESS_KEY')]) {
        withEnv(["AWS_DEFAULT_REGION=${region}",
                 'TF_IN_AUTOMATION=1',
                 'TF_INPUT=0',
                 "TF_PLUGIN_CACHE_DIR=${pluginCache}"]) {

            List<String> envVars = ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY',
                                    'AWS_DEFAULT_REGION', 'TF_IN_AUTOMATION',
                                    'TF_INPUT', 'TF_PLUGIN_CACHE_DIR']

            // Idempotent: reuses the backend configured by the plan stage and
            // fails (instead of migrating) if the backend configuration changed.
            // Never -reconfigure / -migrate-state / -upgrade.
            echo "terraform init (S3 backend) -> ${root}"
            runInContainer(image: image,
                           workDir: root,
                           command: 'init -backend=true -no-color -input=false',
                           envVars: envVars,
                           timeout: timeoutMinutes)

            echo "terraform apply ${planPath} -> ${root}"
            try {
                runInContainer(image: image,
                               workDir: root,
                               command: "apply -no-color -input=false -lock=true ${planFile}",
                               envVars: envVars,
                               timeout: timeoutMinutes)
            } catch (Exception e) {
                // The original failure is preserved (rethrown unchanged). The
                // AccessDenied guidance is echoed ONLY for that case: an
                // interruption (timeout, abort) or any other error does not get it.
                echo "terraformApply: the apply of ${root} failed: ${e.message}"
                if (!e.getClass().name.contains('FlowInterruptedException') &&
                    (e.message ?: '').contains('AccessDenied')) {
                    echo 'AccessDenied: record the action and the resource involved ' +
                         'and report them: do NOT widen the IAM policies.'
                }
                throw e
            }
        }
    }

    // ------------------------------------- success: marker, evidence, cleanup
    // Order matters: the marker first, so a failure of the evidence or of the
    // cleanup can never leave a workspace where the same plan could run again.
    try {
        writeFile file: appliedPath,
                  text: "applied build=${build} commit=${env.GIT_COMMIT} at=${createdAt}\n"
    } catch (Exception e) {
        error "terraformApply: the apply of ${root} SUCCEEDED and the INFRASTRUCTURE " +
              "MAY HAVE CHANGED, but the ${appliedPath} marker could not be written " +
              "(${e.message}). Do NOT re-run automatically: inspect the state in AWS " +
              'and the workspace first.'
    }

    writeEvidence(evidence, build, root, planPath, changes, outcome, createdAt, approval)

    try {
        sh "rm -f \"${planPath}\" \"${infoPath}\""
    } catch (Exception e) {
        error "terraformApply: the apply of ${root} SUCCEEDED, but the plan files " +
              "could not be removed (${e.message}). Do NOT re-run automatically: " +
              'inspect the state in AWS and the workspace first.'
    }

    echo "terraformApply: ${root} applied from ${planPath} (build ${build})"
    return [root: root, planFile: planPath, status: outcome]
}

/**
 * Writes and archives the evidence of this run. It only contains metadata
 * (build, branch, commit, root, plan, changes, outcome, date, and the approval
 * when the target requires one): never a credential, never an environment
 * secret and never a Terraform output. A failure is reported explicitly and is
 * NOT retried.
 */
void writeEvidence(String path, String build, String root, String planPath,
                   String changes, String outcome, String createdAt,
                   Map approval = null) {
    String text = """CircleGuard terraform apply record
================================
Build       : ${build}
Branch      : ${env.BRANCH_NAME ?: 'n/a'}
Commit      : ${env.GIT_COMMIT ?: 'n/a'}
Root        : ${root}
Plan        : ${planPath}
Changes     : ${changes}
Outcome     : ${outcome}
Date (UTC)  : ${createdAt}
"""
    if (approval) {
        text += "Approved by : ${approval.approvedBy}\n" +
                "Approved at : ${approval.approvedAt}\n" +
                "Approved sha: ${approval.approvedSha}\n" +
                "Approved bld: ${approval.approvedBuild}\n" +
                "Plan age    : ${approval.planAge} min at apply\n"
    }
    // The two failures are reported differently: whether the evidence exists in
    // the workspace changes what the operator has to do next. Neither is retried.
    String tail = (outcome == 'APPLIED')
            ? "the apply of ${root} SUCCEEDED and the INFRASTRUCTURE MAY HAVE CHANGED, but "
            : "the run of ${root} finished with ${outcome}, but "
    String retry = 'Do NOT re-run automatically: the outcome of this run is in the log above.'

    try {
        writeFile file: path, text: text
    } catch (Exception e) {
        error "terraformApply: ${tail}the evidence could NOT be written in ${path} " +
              "(${e.message}). ${retry}"
    }
    try {
        archiveArtifacts artifacts: path, allowEmptyArchive: false
    } catch (Exception e) {
        error "terraformApply: ${tail}the evidence WAS written in ${path} but could " +
              "NOT be archived (${e.message}). ${retry}"
    }
}

/**
 * Verifies that the approval persisted by `terraformApproval` belongs to THIS
 * plan and THIS build, that neither the plan nor the approval has expired, and
 * that the approval does not predate the plan (createdAt <= approvedAt <= now;
 * equality is allowed). Returns the age of the plan in minutes, used as evidence.
 *
 * Every check raises `error`, so it fails closed BEFORE withCredentials, before
 * `terraform init` and before `terraform apply`. The sidecar build/commit/root
 * and its status were already verified by the caller against this execution.
 *
 * The validity window reuses `terraformApprovalMaxAgeMinutes` (maxAgeMinutes)
 * instead of a new setting: there is no dedicated parameter (and the
 * configuration is out of scope for this step), one window keeps one rule to
 * reason about, and because an approval is always produced AFTER the plan, the
 * plan age is always the dominant constraint while the approval age adds
 * protection against a tampered or stale TF_APPROVED_AT.
 */
long checkApproval(String build, String root, Map info, String planHash, int maxAgeMinutes) {
    // 1) the four values written by terraformApproval must exist. `== null` (and
    //    not `!value`) distinguishes "the approval stage never ran" from "it ran
    //    but produced an empty value", which is diagnosed below.
    if (env.TF_APPROVED_BY == null) {
        error 'terraformApply: the target requires an approval but TF_APPROVED_BY ' +
              'is not set: run the Terraform approval stage first'
    }
    if (env.TF_APPROVED_AT == null) {
        error 'terraformApply: the target requires an approval but TF_APPROVED_AT ' +
              'is not set: run the Terraform approval stage first'
    }
    if (env.TF_APPROVED_PLAN_SHA == null) {
        error 'terraformApply: the target requires an approval but TF_APPROVED_PLAN_SHA ' +
              'is not set: run the Terraform approval stage first'
    }
    if (env.TF_APPROVED_BUILD == null) {
        error 'terraformApply: the target requires an approval but TF_APPROVED_BUILD ' +
              'is not set: run the Terraform approval stage first'
    }

    // 2) identity of the approver
    String approvedBy = env.TF_APPROVED_BY
    if (!approvedBy.trim() || approvedBy == 'null') {
        error 'terraformApply: the approval carries no valid identity ' +
              '(TF_APPROVED_BY): refusing to apply'
    }

    // 3) approval date: valid and not in the future
    java.time.Instant approvedAt
    try {
        approvedAt = java.time.Instant.parse(env.TF_APPROVED_AT)
    } catch (Exception e) {
        error "terraformApply: invalid TF_APPROVED_AT ('${env.TF_APPROVED_AT}'): " +
              'refusing to apply'
    }
    java.time.Instant now = java.time.Instant.now()
    if (approvedAt.isAfter(now)) {
        error "terraformApply: the approval is dated in the future " +
              "(${env.TF_APPROVED_AT}): refusing to apply"
    }

    // 4) the approval belongs to THIS build and to THIS plan
    if (env.TF_APPROVED_BUILD != build) {
        error "terraformApply: the approval belongs to build ${env.TF_APPROVED_BUILD}, " +
              "this is build ${build}: refusing to apply"
    }
    if (!env.TF_PLAN_SHA256) {
        error 'terraformApply: TF_PLAN_SHA256 is not set: refusing to apply an approval ' +
              'that cannot be tied to the plan'
    }
    if (env.TF_APPROVED_PLAN_SHA != env.TF_PLAN_SHA256) {
        error "terraformApply: the approval is for sha256 ${env.TF_APPROVED_PLAN_SHA} " +
              "but the plan stage published ${env.TF_PLAN_SHA256}: refusing to apply"
    }
    if (info.sha256 != env.TF_PLAN_SHA256) {
        error "terraformApply: the sidecar says sha256=${info.sha256} but the plan " +
              "stage published ${env.TF_PLAN_SHA256}: refusing to apply"
    }
    if (planHash != env.TF_PLAN_SHA256) {
        error "terraformApply: the SHA-256 of the plan file is ${planHash} but the " +
              "approval is for ${env.TF_PLAN_SHA256}: the plan changed after it was " +
              'approved'
    }

    // 5) freshness of the plan
    java.time.Instant created
    try {
        created = java.time.Instant.parse(info.createdAt)
    } catch (Exception e) {
        error "terraformApply: invalid createdAt ('${info.createdAt}'): refusing to apply"
    }
    if (created.isAfter(now)) {
        error "terraformApply: the plan is dated in the future (${info.createdAt}): " +
              'refusing to apply'
    }
    // The approval cannot predate the plan it approves: createdAt <= approvedAt
    // (equality is allowed: both timestamps can be the same instant).
    if (approvedAt.isBefore(created)) {
        error "terraformApply: the approval (${env.TF_APPROVED_AT}) is older than the " +
              "plan it approves (${info.createdAt}): the approval does not correspond " +
              'to this plan in time, refusing to apply'
    }
    long planAge = java.time.Duration.between(created, now).toMinutes()
    if (planAge > maxAgeMinutes) {
        error "terraformApply: the plan is ${planAge} minutes old, more than the " +
              "maximum of ${maxAgeMinutes}: it expired, request a new build"
    }

    // 6) freshness of the approval (same window, see the doc of this method).
    //    Unreachable while the plan-age check and the createdAt <= approvedAt
    //    rule above hold (an approval is always produced after the plan): kept
    //    as defence in depth against a tampered `createdAt`.
    long approvalAge = java.time.Duration.between(approvedAt, now).toMinutes()
    if (approvalAge > maxAgeMinutes) {
        error "terraformApply: the approval is ${approvalAge} minutes old, more than " +
              "the maximum of ${maxAgeMinutes}: it expired, request a new build"
    }

    return planAge
}
