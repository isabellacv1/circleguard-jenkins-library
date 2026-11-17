/**
 * Static validation of the Terraform configuration (HU 1 / HU 2, no plan/apply).
 *
 * Runs, inside the official Terraform image pinned to a concrete version:
 *
 *   0. free-space check of the workspace (ABORTS before running Terraform)
 *   1. terraform fmt  -check -recursive -no-color <fmtPath>   (never writes)
 *   2. terraform init -backend=false -no-color                (per root)
 *   3. terraform validate -no-color                           (per root)
 *
 * Guarantees:
 *   - No AWS credentials are needed: `-backend=false` never contacts S3 and
 *     `validate` only evaluates the configuration.
 *   - No state is read, written or migrated.
 *   - No `plan`, `apply` or `destroy` is ever executed.
 *   - No `.tf` file is modified: `fmt` runs with `-check` (a file that needs
 *     formatting fails the build instead of being rewritten).
 *   - No `-upgrade`: `.terraform.lock.hcl` is never rewritten to new versions.
 *
 * Free space (H3): `terraform init` downloads the AWS provider, whose binary is
 * ~772 MB. Without a plugin cache every root stores its own copy (4 roots would
 * need ~3.09 GB, more than the free space of the Jenkins host), so the provider
 * is downloaded once into TF_PLUGIN_CACHE_DIR and Terraform links it into each
 * root. The check runs FIRST and aborts before any Terraform command (and before
 * any download) when the workspace has less than `minFreeSpaceMB` available.
 *
 * Plugin cache (documented behaviour, HashiCorp docs "plugin_cache_dir"):
 *   - `terraform init` checks the cache first; if the plugin is there it is
 *     reused, otherwise it is downloaded into the cache and then linked from
 *     `.terraform/providers/...` ("Terraform will use symbolic links to avoid
 *     storing a separate copy of a cached plugin in multiple directories").
 *   - What stays in `.terraform`: the `providers/` entries (symlinks to the
 *     cache), `modules/modules.json` (the modules of this project are local, so
 *     nothing is copied) and the `environment` marker. No state.
 *   - Expected disk with the cache: ~772 MB in `<workspace>/.terraform-plugin-cache`
 *     plus a few KB per root, instead of 772 MB per root.
 *   - The cache lives in the workspace of the job: persistent for dev/main and
 *     isolated per job (no sharing between concurrent builds).
 *
 * The image must be >= 1.10 because the backends of envs/<env> declare
 * `use_lockfile = true` (verified version: 1.17.2).
 *
 * Usage:
 *   terraformValidate()                                    // DEV only by default
 *   terraformValidate(roots: ['infra/terraform/envs/dev'],
 *                     fmtPath: 'infra/terraform',
 *                     minFreeSpaceMB: 1500,
 *                     image: 'hashicorp/terraform:1.17.2')
 */
def call(Map params = [:]) {
    String image = params.image ?: 'hashicorp/terraform:1.17.2'
    List<String> roots = params.roots ?: []
    String fmtPath = params.fmtPath ?: 'infra/terraform'
    int timeoutMinutes = params.timeout ?: 15
    int minFreeSpaceMB = params.minFreeSpaceMB ?: 1500
    String pluginCacheName = params.pluginCacheDir ?: '.terraform-plugin-cache'

    if (!roots) {
        error 'terraformValidate: roots are required'
    }
    if (!env.WORKSPACE) {
        error 'terraformValidate: no workspace available'
    }
    if (!fileExists(fmtPath)) {
        error "terraformValidate: ${fmtPath} does not exist in the workspace"
    }

    // Fail fast: every root must exist before anything runs.
    for (String root : roots) {
        if (!fileExists(root)) {
            error "terraformValidate: root ${root} does not exist in the workspace"
        }
    }

    // 0) Free space: abort BEFORE any terraform command (and any download).
    // Only sizes are reported: no path of the host, no credential, no state data.
    String df = sh(script: "df -Pk \"${env.WORKSPACE}\"", returnStdout: true)
    long availableMB = freeSpaceMB(df)
    if (availableMB < 0) {
        error 'terraformValidate: unable to read the free space of the workspace'
    }
    if (availableMB < minFreeSpaceMB) {
        error "terraformValidate: ${availableMB} MB free in the workspace, " +
              "${minFreeSpaceMB} MB required (Terraform would download ~772 MB of providers). " +
              'Aborting before running Terraform: nothing was downloaded.'
    }
    echo "terraformValidate: ${availableMB} MB available (minimum ${minFreeSpaceMB} MB)"

    // 1) Plugin cache directory, created on the controller inside the workspace
    // (the container reaches it at /ws/<name> through the same mount).
    sh "mkdir -p \"${env.WORKSPACE}/${pluginCacheName}\""
    String pluginCache = "/ws/${pluginCacheName}"

    echo "Terraform validation with ${image}"

    // fmt -check never writes: it only fails when a file is not formatted.
    echo "terraform fmt -check -> ${fmtPath}"
    runInContainer(image: image,
                   command: "fmt -check -recursive -no-color ${fmtPath}",
                   timeout: timeoutMinutes)

    for (String root : roots) {
        // -backend=false: the providers are installed locally, S3 is never touched.
        // TF_PLUGIN_CACHE_DIR reuses the already downloaded provider.
        echo "terraform init -backend=false -> ${root}"
        withEnv(["TF_PLUGIN_CACHE_DIR=${pluginCache}"]) {
            runInContainer(image: image,
                           workDir: root,
                           command: 'init -backend=false -no-color',
                           envVars: ['TF_PLUGIN_CACHE_DIR'],
                           timeout: timeoutMinutes)
        }

        echo "terraform validate -> ${root}"
        runInContainer(image: image,
                       workDir: root,
                       command: 'validate -no-color',
                       timeout: timeoutMinutes)
    }

    echo "Terraform validation OK (${roots.size()} root(s): ${roots.join(', ')})"
}

/**
 * Available space in MB from the output of `df -Pk` (column "Available", in KB).
 * Returns -1 when the output cannot be parsed, so the caller aborts instead of
 * running Terraform with an unknown amount of space.
 */
long freeSpaceMB(String dfOutput) {
    List<String> lines = (dfOutput ?: '').readLines().findAll { it.trim() }
    if (lines.isEmpty()) {
        return -1L
    }
    List<String> columns = lines.last().trim().split(/\s+/) as List
    if (columns.size() < 4 || !columns[3].isLong()) {
        return -1L
    }
    // intdiv: Groovy `/` on integers returns BigDecimal, which would break the cast
    return (columns[3] as long).intdiv(1024L)
}
