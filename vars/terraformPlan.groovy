/**
 * Runs `terraform plan` against the REAL S3 backend and keeps the saved plan in
 * the workspace of the same build. Phase 1: plan only, no apply, no artifacts.
 *
 * Runs, inside the official Terraform image pinned to a concrete version:
 *
 *   0. free-space check of the workspace (ABORTS before running Terraform)
 *   1. mkdir of the shared plugin cache (same directory as terraformValidate)
 *   2. rm of the plan of a previous build (a stale plan must never survive)
 *   3. terraform init  -backend=true -no-color -input=false   (real S3 backend)
 *   4. terraform plan  -no-color -input=false -lock=true -detailed-exitcode
 *                      -out=<root>/ci-<env>-b<build>.tfplan
 *   5. sidecar <plan>.info with build, commit, root, changes, status, sha256
 *      and date (sha256sum is required: without it the step fails closed)
 *
 * Backend (S3): `init` contacts the bucket declared in `<root>/versions.tf`,
 * reads the state and creates the `.tflock` (`use_lockfile = true`). It never
 * uses `-backend=false` (that is `terraformValidate`), and never
 * `-reconfigure`/`-migrate-state` (docs/operaciones/terraform.md §2.4: both can
 * silently repoint or copy the state and need explicit authorisation).
 *
 * Credentials: `aws-terraform-credentials` (username = Access Key ID,
 * password = Secret Access Key) is bound ONLY around `init` and `plan` with
 * `withCredentials()`, and its values are handed to `runInContainer` BY NAME
 * (`envVars: [...]`), so they never appear in a command line nor in the build
 * log. Nothing outside that block can see them.
 *
 * Environment injected by name: `AWS_DEFAULT_REGION`, `TF_IN_AUTOMATION=1`,
 * `TF_INPUT=0` and `TF_PLUGIN_CACHE_DIR` (scoped with `withEnv`, exactly like
 * terraformValidate, so the value is not part of any command either).
 *
 * Exit codes of `-detailed-exitcode` (terraformPlan fails on anything but 0/2):
 *   0 -> plan OK, no changes
 *   2 -> plan OK, changes pending (reported as `changes: true`)
 *   1 -> error (provider, backend, AccessDenied, ...)
 * On AccessDenied the message asks to record the action and the resource: the
 * IAM policies are NEVER widened from a build failure.
 *
 * Free space and plugin cache: the free-space parser is REUSED from
 * `terraformValidate.freeSpaceMB` (same helper, same threshold semantics) and
 * the cache directory is the same (`<workspace>/.terraform-plugin-cache`, i.e.
 * `/ws/.terraform-plugin-cache` inside the container), so the ~772 MB AWS
 * provider downloaded by `init` is shared with the validate stage and never
 * duplicated.
 *
 * Evidence: the plan file stays in the workspace of the build
 * (`<root>/ci-<env>-b<build>.tfplan`, extension ignored by `.gitignore`) and is
 * NEVER archived: it must not be downloadable, only reviewable in the workspace
 * of the same build. The `<plan>.info` sidecar carries its provenance (build,
 * commit, root, changes, status, date) so `terraformApply` can prove that the
 * plan belongs to this build and this revision before applying it.
 *
 * Usage:
 *   terraformPlan(root: 'infra/terraform/envs/dev',
 *                 credentialsId: 'aws-terraform-credentials',
 *                 image: 'hashicorp/terraform:1.17.2',
 *                 region: 'us-east-1')
 *
 * Returns [root: ..., planFile: ..., planInfo: ..., changes: true|false,
 * status: 0|2].
 * Raises `error` when the plan fails or the plan file was not written.
 */
def call(Map params = [:]) {
    String image = params.image ?: 'hashicorp/terraform:1.17.2'
    String root = params.root
    // containsKey: an explicitly empty/null credential id must FAIL instead of
    // silently falling back to the default (a plan must never run anonymously).
    String credentialsId = params.containsKey('credentialsId') ? params.credentialsId
                                                              : 'aws-terraform-credentials'
    String region = params.region ?: 'us-east-1'
    int timeoutMinutes = params.timeout ?: 20
    int minFreeSpaceMB = params.minFreeSpaceMB ?: 1500
    String pluginCacheName = params.pluginCacheDir ?: '.terraform-plugin-cache'
    String planName = params.planFile

    if (!root) {
        error 'terraformPlan: root is required'
    }
    if (!credentialsId) {
        error 'terraformPlan: credentialsId is required'
    }
    if (!env.WORKSPACE) {
        error 'terraformPlan: no workspace available'
    }
    // The root and the file names are interpolated into shell commands: only a
    // relative path made of path characters is accepted (no absolute path, no
    // `..`, so nothing can escape the workspace of the job).
    if (root.startsWith('/') || root.split('/').contains('..') || !(root ==~ /[A-Za-z0-9._\/-]+/)) {
        error "terraformPlan: root must be a relative path inside the workspace " +
              "without '..': ${root}"
    }
    if (!(pluginCacheName ==~ /[A-Za-z0-9._-]+/)) {
        error "terraformPlan: invalid plugin cache directory name: ${pluginCacheName}"
    }

    // Fail fast: the root must exist and must declare the backend (`backend
    // "s3"` lives in versions.tf of every environment).
    if (!fileExists(root)) {
        error "terraformPlan: root ${root} does not exist in the workspace"
    }
    String versionsFile = "${root}/versions.tf"
    if (!fileExists(versionsFile)) {
        error "terraformPlan: ${versionsFile} does not exist in the workspace, " +
              "the backend of ${root} cannot be initialised"
    }

    // Default plan name: ci-<env>-b<build>.tfplan (e.g. infra/terraform/envs/dev
    // in build 47 -> ci-dev-b47.tfplan), always inside the root and always with
    // the extension ignored by .gitignore (`*.tfplan`). The build number is part
    // of the name on purpose: the apply step of another build cannot consume it.
    String build = env.BUILD_NUMBER ?: 'nobuild'
    if (!planName) {
        planName = "ci-${root.tokenize('/').last()}-b${build}.tfplan"
    }
    if (!(planName ==~ /[A-Za-z0-9._-]+/) || !planName.endsWith('.tfplan')) {
        error "terraformPlan: planFile must be a plain name ending in .tfplan: ${planName}"
    }
    String planPath = "${root}/${planName}"
    // Sidecar with the provenance of the plan (build, commit, root, changes,
    // status, date): terraformApply validates it before running anything.
    String infoPath = "${planPath}.info"

    // 0) Free space BEFORE any Terraform command and before the credentials are
    //    bound: `init` downloads ~772 MB of providers on the first build.
    //    The parser is the one of terraformValidate (reused, not duplicated).
    String df = sh(script: "df -Pk \"${env.WORKSPACE}\"", returnStdout: true)
    long availableMB = terraformValidate.freeSpaceMB(df)
    if (availableMB < 0) {
        error 'terraformPlan: unable to read the free space of the workspace'
    }
    if (availableMB < minFreeSpaceMB) {
        error "terraformPlan: ${availableMB} MB free in the workspace, " +
              "${minFreeSpaceMB} MB required (Terraform downloads ~772 MB of providers). " +
              'Aborting before running Terraform: nothing was downloaded.'
    }
    echo "terraformPlan: ${availableMB} MB available (minimum ${minFreeSpaceMB} MB)"

    // 1) Plugin cache: created on the controller inside the workspace, reached
    //    by the container at /ws/<name> through the same mount as terraformValidate.
    sh "mkdir -p \"${env.WORKSPACE}/${pluginCacheName}\""
    String pluginCache = "/ws/${pluginCacheName}"

    // 2) The plan of a previous build is removed (and its sidecar): an apply can
    //    only ever use a plan produced by THIS build.
    sh "rm -f \"${planPath}\" \"${infoPath}\""

    echo "terraform plan of ${root} with ${image}"

    int status = -1

    // 3) Credentials are visible only inside this block, and only to the two
    //    commands that need AWS (init reads the backend, plan refreshes).
    withCredentials([usernamePassword(credentialsId: credentialsId,
                                      usernameVariable: 'AWS_ACCESS_KEY_ID',
                                      passwordVariable: 'AWS_SECRET_ACCESS_KEY')]) {
        withEnv(["AWS_DEFAULT_REGION=${region}",
                 'TF_IN_AUTOMATION=1',
                 'TF_INPUT=0',
                 "TF_PLUGIN_CACHE_DIR=${pluginCache}"]) {

            // Passed BY NAME: runInContainer expands them to `-e <name>` and the
            // values never reach the command line or the build log.
            List<String> envVars = ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY',
                                    'AWS_DEFAULT_REGION', 'TF_IN_AUTOMATION',
                                    'TF_INPUT', 'TF_PLUGIN_CACHE_DIR']

            echo "terraform init (S3 backend) -> ${root}"
            runInContainer(image: image,
                           workDir: root,
                           command: 'init -backend=true -no-color -input=false',
                           envVars: envVars,
                           timeout: timeoutMinutes)

            echo "terraform plan -out=${planPath} -> ${root}"
            status = runInContainer(image: image,
                                    workDir: root,
                                    command: "plan -no-color -input=false -lock=true " +
                                             "-detailed-exitcode -out=${planName}",
                                    envVars: envVars,
                                    timeout: timeoutMinutes,
                                    returnStatus: true)
        }
    }

    // 4) Interpretation of -detailed-exitcode.
    if (status == 0) {
        echo "terraformPlan: plan finished with NO changes (${planPath})"
    } else if (status == 2) {
        echo "terraformPlan: plan finished with CHANGES pending (${planPath})"
    } else {
        error "terraformPlan: terraform plan failed (exit ${status}) for ${root}. " +
              'Check the container output above. If it reports AccessDenied, record ' +
              'the action and the resource involved and report them: do NOT widen ' +
              'the IAM policies to make the build pass.'
    }

    // 5) Fail safe: without the file a later apply would run a stale plan.
    if (!fileExists(planPath)) {
        error "terraformPlan: Terraform did not write the plan file ${planPath}"
    }

    // 5.5) SHA-256 of the plan: terraformApply recomputes it and refuses a plan
    //      whose content changed after this point. Fail CLOSED when sha256sum is
    //      not available: without it the provenance of the file cannot be proven,
    //      so no sidecar (and no plan) is left behind.
    String planHash = ''
    try {
        String output = sh(script: "sha256sum \"${planPath}\"", returnStdout: true)
        planHash = output.trim().split(/\s+/)[0] ?: ''
    } catch (Exception e) {
        error "terraformPlan: unable to compute the SHA-256 of ${planPath} " +
              "(${e.message}): sha256sum is required to prove the provenance of " +
              'the plan, aborting before the sidecar is written.'
    }
    if (!(planHash ==~ /[0-9a-f]{64}/)) {
        error "terraformPlan: unexpected SHA-256 for ${planPath}: '${planHash}'"
    }

    // 6) Sidecar with the provenance of THIS plan (build, commit, root, changes,
    //    status, sha256, date): terraformApply validates every one of them before
    //    running any command. Written only after a successful plan.
    //    java.time instead of Date.format(String, TimeZone): available in every
    //    Groovy version (the DGM overload is not) and always UTC.
    String createdAt = java.time.Instant.now().toString()
    writeFile file: infoPath,
              text: "build=${build}\n" +
                    "commit=${env.GIT_COMMIT ?: 'unknown'}\n" +
                    "root=${root}\n" +
                    "changes=${status == 2}\n" +
                    "status=${status}\n" +
                    "sha256=${planHash}\n" +
                    "createdAt=${createdAt}\n"

    return [root    : root,
            planFile: planPath,
            planInfo: infoPath,
            changes : status == 2,
            status  : status]
}
