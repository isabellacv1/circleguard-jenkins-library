# CircleGuard Jenkins Shared Library

Shared Library with the CI pipeline of [CircleGuard](https://github.com/isabellacv1/final-project-A00401116-A00401334-A00401749-A00402018).
Based on the structure of the team's workshop library (`vars/` steps + typed config in `src/`).

## Structure

```
src/org/circleguard/ci/PipelineConfig.groovy   parameters and defaults
vars/circleguardPipeline.groovy                full pipeline (entry point)
vars/gradlew.groovy                            runs ./gradlew tasks
vars/configureTestcontainers.groovy            Testcontainers networking inside Jenkins
vars/publishTestReports.groovy                 JUnit results + test/JaCoCo reports
vars/sonarAnalysis.groovy                      SonarQube analysis + quality gate (optional)
vars/runInContainer.groovy                     runs a command in a container with access to the workspace
vars/terraformValidate.groovy                  terraform fmt -check + init -backend=false + validate
vars/trivyScan.groovy                          trivy config (IaC), blocks on HIGH/CRITICAL
vars/resolveVersion.groovy                     semantic version for the images (from release tags)
vars/publishImages.groovy                      docker build + push to the Nexus registry
vars/ensureBuildx.groovy                       installs the Docker buildx plugin if missing (BuildKit)
vars/notifyDiscord.groovy                      Discord notification of the build result
```

## Usage

`Jenkinsfile` in the project:

```groovy
@Library('circleguard-pipeline-library@main') _

circleguardPipeline(
    integrationTests: true,
    sonar: false
)
```

### Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `integrationTests` | `true` | Runs `./gradlew integrationTest`. |
| `sonar` | `false` | Runs the SonarQube analysis and waits for the quality gate. |
| `sonarServer` | `CircleGuard-SonarQube` | SonarQube server name configured in Jenkins. |
| `sonarProjectKey` | `circleguard` | SonarQube project key. |
| `buildTimeout` | `30` | Build stage timeout (minutes). |
| `testTimeout` | `45` | Tests stage timeout (minutes). |
| `integrationTimeout` | `30` | Integration tests stage timeout (minutes). |
| `buildsToKeep` | `20` | Number of builds kept by Jenkins. |
| `publish` | `false` | Builds and pushes the Docker images to the registry. |
| `publishBranches` | `['dev', 'main']` | Branches that publish images (PRs never publish). |
| `registry` | `localhost:8082` | Docker registry (Nexus `docker-hosted` HTTP connector). |
| `registryCredentialsId` | `nexus-credential` | Jenkins credential with push access to the registry. |
| `images` | 5 core services + web | List of `[name, dockerfile, context]` to build. |
| `publishTimeout` | `40` | Publish stage timeout (minutes). |
| `discordCredentialsId` | `discord-webhook-url` | Jenkins Secret text credential with the Discord webhook URL. Empty disables it. |
| `deploy` | `false` | Deploys the published images to an AWS environment (requires `publish: true`). |
| `environment` | `dev` | Target environment: `dev`, `stage` or `prod`. Read from `deploy/environments/<env>.env`. |
| `deployBranches` | `['dev']` | Branches that run the deploy and verification stages. |
| `deployCredentialId` | `${environment}-credential` | SSH credential (`dev-credential`, `stage-credential`, `prod-credential`). |
| `deployTimeout` | `20` | Deploy stage timeout (minutes). |
| `verifyTimeout` | `15` | Verification stage timeout (minutes). |
| `healthRetries` | `20` | Attempts per service before the deployment is rejected. |
| `healthIntervalSeconds` | `10` | Seconds between attempts. |
| `services` | gateway/auth/identity/form/promotion/web | Components checked after the deployment (`name`, `port`, `path`). |
| `e2e` | `true` | Runs the Playwright end to end tests against the deployed `dev`. |
| `e2eTimeout` | `20` | E2E stage timeout (minutes). |
| `e2eCredentialsId` | `e2e-credential` | Username/password of a test user of the application. |
| `e2eImage` | `mcr.microsoft.com/playwright:v1.65.0-noble` | Image used to run the tests (Jenkins has no Node.js). |
| `promote` | `false` | Enables the promotion stages `dev -> stage -> prod`. |
| `stageApproval` | `false` | `false` promotes to stage automatically after the E2E tests. |
| `prodApproval` | `true` | `true` waits for a manual approval (`input`) before promoting to prod. |
| `approvalTimeout` | `240` | Minutes the approver has to answer the `input`. **The global build timeout (120 min) caps the effective wait**: the promotion never gets the full 240 minutes (see *Concurrency: builds queue*). |
| `promotionRecordFile` | `promotion-record.txt` | Artifact with the evidence of every promotion. |
| `terraformValidate` | `false` | Runs `terraform fmt -check`, `terraform init -backend=false` and `terraform validate` on every root. No AWS credentials, no `plan`/`apply`. |
| `terraformImage` | `hashicorp/terraform:1.17.2` | Pinned Terraform image. Must be `>= 1.10`: the backends declare `use_lockfile`. |
| `terraformRoots` | `infra/terraform/envs/dev` | Roots validated by the step (paths relative to the workspace). **Only DEV** until the first real run is validated; STAGE, PROD and `backend-bootstrap` are added later. |
| `terraformFmtPath` | `infra/terraform` | Directory checked with `terraform fmt -check -recursive`. |
| `terraformValidateTimeout` | `15` | Terraform stage timeout (minutes). |
| `terraformMinFreeSpaceMB` | `1500` | Free space (MB) required in the workspace **before** any Terraform command runs. |
| `trivyScan` | `false` | Runs `trivy config`; a HIGH/CRITICAL finding fails the build. |
| `trivyImage` | `aquasec/trivy:0.76.2` | Pinned image of the Trivy **tool** (the scanner) used by the IaC scan **and** by the image scan. It is **not** the image being scanned. |
| `trivyImageScan` | `false` | Scans every image **between `docker build` and `docker push`** and blocks on HIGH/CRITICAL (opt-in, runs inside `Publish images`). |
| `trivyImageSeverity` | `HIGH,CRITICAL` | Severities that block the publication of an image (configured apart from `trivySeverity`, which is for the IaC scan). |
| `trivyImageBranches` | `['dev', 'main']` | Branches that scan before pushing (⊆ `publishBranches`; PRs never reach the stage). The scan requires `env.BRANCH_NAME` to exist **and** to be listed here: a missing or unlisted branch skips it. |
| `trivyImageTimeout` | `15` | Timeout of a single image scan (minutes). |
| `trivyImageIgnoreFile` | `.trivyignore.yaml` | Ignore file with the documented exceptions (the same file as the IaC scan, section `vulnerabilities:`). Passed with `--ignorefile` only when it exists. |
| `trivyPaths` | `['infra/terraform']` | Directories scanned (Trivy accepts one target per invocation). |
| `trivySeverity` | `HIGH,CRITICAL` | Severities that block the build. |
| `trivyTimeout` | `15` | Trivy stage timeout (minutes). |
| `terraformPlan` | `false` | Runs `terraform init -backend=true` (real S3 backend) and `terraform plan -out=...` for a single root. Needs AWS credentials; **never** runs `apply` and never archives the plan. |
| `terraformPlanRoot` | `infra/terraform/envs/dev` | Single root planned. Deliberately independent from `terraformRoots`, so a root added to the validate list is not planned automatically. |
| `terraformPlanBranches` | `['dev']` | Branches that run the plan stage. **PRs and every other branch are excluded** (the stage requires the flag AND the branch). |
| `terraformAwsCredentialsId` | `aws-terraform-credentials` | Username/password credential (Access Key ID / Secret Access Key) bound with `withCredentials` only around the Terraform commands. |
| `terraformAwsRegion` | `us-east-1` | Value of `AWS_DEFAULT_REGION`, injected by name. |
| `terraformPlanTimeout` | `20` | Plan stage budget and per-command timeout (minutes). |
| `terraformApply` | `false` | Applies **the plan of the same build** with `terraform apply -lock=true` (DEV only in this phase; STAGE/PROD not enabled). |
| `terraformApplyRoot` | `infra/terraform/envs/dev` | Single root applied. Independent from `terraformPlanRoot`, so enabling another environment is always an explicit decision. |
| `terraformApplyBranches` | `['dev']` | Branches that apply. **PRs and every other branch are excluded** (the stage requires the flag AND the branch). |
| `terraformApplyTimeout` | `30` | Apply command timeout; the stage budget is `2 ×` this value (init + apply). |
| `terraformApproval` | `false` | Master switch of the manual approval that will gate an environment apply. **S1: configuration only — the approval step does not exist yet.** |
| `terraformApprovalTimeout` | `30` | Minutes the approver has to answer (must be `> 0`, otherwise the configuration is rejected). |
| `terraformApprovalSubmitter` | `admin` | Users/groups allowed to approve (passed to `submitter` of `input`). Must not be empty, otherwise the configuration is rejected. |
| `terraformApprovalMaxAgeMinutes` | `60` | A plan older than this is rejected instead of applied (must be `> 0`). |
| `terraformApplyProdRoot` | `infra/terraform/envs/prod` | PROD root used by the three PROD stages; inert until `terraformApplyProd` (and, for the approval, `terraformApproval`) is enabled. |
| `terraformApplyProdBranches` | `['main']` | Branch for the PROD target: PROD is only ever selected from `main` (any other branch, or a branch shared with DEV, fails the build). |
| `terraformApplyProd` | `false` | PROD apply switch: **off**. Independent from `terraformApprovalProd`. |
| `terraformApprovalProd` | `false` | PROD approval switch: **off**. Both PROD switches must be enabled explicitly. |

### Stages

| Stage | What it does |
|-------|--------------|
| Checkout | `checkout scm` |
| Build | `./gradlew assemble` |
| Tests | `./gradlew test --continue` |
| Integration tests | `./gradlew integrationTest --continue` (if `integrationTests`) |
| SonarQube | analysis + quality gate (if `sonar`) |
| Terraform validate | `fmt -check`, `init -backend=false` and `validate` of every Terraform root (if `terraformValidate`) |
| Trivy IaC | `trivy config` of `trivyPaths`; HIGH/CRITICAL findings fail the build and the report is archived (if `trivyScan`) |
| Terraform plan DEV | `terraform init -backend=true` + `terraform plan -detailed-exitcode -out=<root>/ci-<env>-b<build>.tfplan` against the real S3 backend, with `aws-terraform-credentials` injected **by name** (stage `Terraform plan`, if `terraformPlan` and branch in `terraformPlanBranches`) |
| Terraform plan PROD | same plan step for the PROD root, resolved from the branch (`main` only, and only when `terraformApplyProd` **and** `terraformPlan` are on; stage `Terraform plan PROD`) |
| Terraform approval PROD | manual `input` between the PROD plan and the PROD apply (stage `Terraform approval`; requires `terraformApplyProd` **and** `terraformApproval` **and** `terraformApprovalProd`, a plan with changes and a full approval window) |
| Terraform apply DEV | `terraform init -backend=true` + `terraform apply -lock=true ci-<env>-b<build>.tfplan`, the plan of **this** build only, **never an approval** (stage `Terraform apply`, if `terraformApply` and branch in `terraformApplyBranches`) |
| Terraform apply PROD | `terraform apply -lock=true` for the PROD root, only with a valid approval of **this** build (`requireApproval: true`; stage `Terraform apply PROD`) |
| Publish images | `docker build` + `docker push` of every image (if `publish` and branch in `publishBranches`); each image is scanned with Trivy **between the build and the push** when `trivyImageScan` is enabled |
| Deploy | Copies the compose files to the target host over SSH and runs `docker compose up -d --wait` with the published images (if `deploy` and branch in `deployBranches`) |
| Verify deployment | HTTP check of every component with retries; the build fails if a service does not answer (if `deploy`) |
| Smoke tests | Functional HTTP checks against the target host, with a JUnit report (if `deploy` and `smokeTests`) |
| E2E tests | Playwright tests in a container against the deployed `dev` (condition to promote, if `e2e`) |
| Promote to stage | Deploys the **same version** to `stage` and verifies it; manual `input` only if `stageApproval` |
| Promote to prod | Deploys the **same version** to `prod`, verifies it and archives `promotion-record.txt`; always behind a manual `input` |

## Static validation of the infrastructure as code (Terraform + Trivy)

Two optional stages that validate the Terraform code **before** anything is built.
Both are **off by default** (`terraformValidate: false`, `trivyScan: false`) so the
behaviour of the pipeline does not change until the project opts in, and neither
of them needs AWS credentials.

```groovy
circleguardPipeline(
    // ...
    terraformValidate: true,
    trivyScan: true
)
```

| Step | Image (pinned) | Commands |
|------|----------------|----------|
| `terraformValidate` | `hashicorp/terraform:1.17.2` (≥ 1.10: `use_lockfile`) | `terraform fmt -check -recursive -no-color infra/terraform` · `terraform init -backend=false -no-color` · `terraform validate -no-color` (per root) |
| `trivyScan` | `aquasec/trivy:0.76.2` | `trivy config <path> --severity HIGH,CRITICAL --exit-code 1 --format table --output trivy-iac-report-<build><-path>.txt --quiet --cache-dir /ws/.trivy-cache --skip-dirs ... --skip-files ...` |

### Workspace isolation

`runInContainer` and `runE2E` do **not** mount the whole `circleguard-jenkins-home`
volume (which holds `credentials.xml`, `secrets/` and the workspaces of every
other job). They mount **only the workspace of the job**, with the
`volume-subpath` option of `--mount`:

```bash
docker run --rm --user $(id -u):$(id -g) -e HOME=/tmp \
  --mount type=volume,source=circleguard-jenkins-home,destination=/ws,volume-subpath=workspace/<job> \
  -w '/ws' <image> <command>
```

The workspace root is `/ws` inside the container (`/jh` in `runE2E`, whose
working directory is `/jh/tests/e2e-playwright`), so steps that need a path in
the workspace (Trivy cache, Terraform plugin cache, the Playwright project) use
that root. Two guards run before the mount: the workspace must live under
`/var/jenkins_home/workspace/` and it must already exist (it is created by
`Checkout`, the first stage).

> ⚠ **`volume-subpath` still needs a real `docker run` to be validated.** It is
> documented by the Docker Engine and supported by the Docker 29.9.3 of the
> host, but no container has been executed yet in this environment. If the mount
> fails, the documented fallback is the previous behaviour: mount the whole
> volume (`-v circleguard-jenkins-home:/jh`) and translate `/var/jenkins_home/...`
> to `/jh/...` — used only as an emergency fallback: since the `runE2E` change,
> **no step mounts the whole volume anymore**.

Rules enforced by the steps:

- **No `plan`, `apply` or `destroy`** is executed by `terraformValidate` or
  `trivyScan`, and `terraformValidate` runs `init` with `-backend=false`, so the
  S3 backend is never contacted and no state is migrated. (The separate
  `Terraform plan` stage described below is the only one that contacts S3.)
- **No `.tf` file is modified**: `fmt` runs with `-check` (a badly formatted file
  fails the build instead of being rewritten) and `init` never uses `-upgrade`, so
  `.terraform.lock.hcl` is not rewritten.
- **The images must be pinned**: `:latest` and untagged images are rejected by
  `runInContainer`.
- **The report is kept and is never stale**: the report is named
  `trivy-iac-report-<build>[<-path>].txt`, so the report of a previous build can
  never be archived as evidence of the current one. It is echoed to the log and
  archived with the build, also when the stage fails, and the error message says
  whether a report was generated or not.
- **No secrets in the log**: `trivy config` only runs the misconfiguration scanner
  (it never scans for secrets), and the state files and saved plans are excluded.
- **The Trivy cache is per job**: it lives in the workspace (`/ws/.trivy-cache`),
  created by the non-root user of the container, so two concurrent builds never
  share the same bbolt database (Trivy fails with *"cache may be in use by another
  process"* when another process holds the lock).
- **The disk is checked first**: `terraformValidate` reads the free space of the
  workspace and aborts **before running any Terraform command** when it is below
  `terraformMinFreeSpaceMB`, reporting only the available space and the threshold.
- **The AWS provider is downloaded once**: `TF_PLUGIN_CACHE_DIR` points to
  `<workspace>/.terraform-plugin-cache` (persistent for dev/main, isolated per
  job). Terraform downloads the ~772 MB provider there once and **links** it into
  `.terraform/providers/...` of each root ("Terraform will use symbolic links to
  avoid storing a separate copy of a cached plugin in multiple directories").
  What stays in `.terraform`: those links, `modules/modules.json` (the modules of
  this project are local) and the `environment` marker — no state. Expected disk:
  ~772 MB in the cache plus a few KB per root, instead of 772 MB per root.

### Exclusions

Always excluded from the scan (passed to Trivy as `--skip-dirs`/`--skip-files`):
`.git`, `.terraform` (downloaded providers/modules), `.trivy-cache` (the cache of
the step itself) and every `*.tfstate*` / `*.tfplan*` file, including the backups
of `backend-bootstrap`.

### Justified exceptions

Never disable the scan globally. If a finding is accepted on purpose, create
`.trivyignore.yaml` in the workspace root with the **specific check id** and the
reason:

```yaml
# accepted: documented in HU2 (state lifecycle), reviewed2026-11-17
- AVD-AWS-0123
```

The step passes the file to Trivy with `--ignorefile` **only when it exists**, so
the repository does not need the file until there is a real exception.

### Tests

`test/StepTests.groovy` covers both steps without Docker, network or AWS (every
Jenkins step is stubbed). See [`test/README.md`](test/README.md):

```bash
java -cp "$(find ~/.gradle -name 'groovy-5*.jar' | head -1)" \
     groovy.ui.GroovyMain test/StepTests.groovy
```

### Image versions

Images are tagged only with a semantic version, never `latest`:

- If the commit has a release tag created by semantic-release (`v1.2.0`, `v1.3.0-dev.2`), that version
  is used: `circleguard/auth-service:1.2.0`.
- Otherwise a pre-release version is built from the last release tag:
  `circleguard/auth-service:1.2.0-build.15.ab12cd3`.

The list of pushed images is archived in every build as `published-images.txt`.

The Dockerfiles use `RUN --mount=type=cache`, which needs BuildKit. `publishImages` calls
`ensureBuildx()`, which downloads a pinned buildx release (checksum verified) into
`~/.docker/cli-plugins` when the Jenkins image does not include it.

The registry must have an HTTP connector (Nexus `docker-hosted`, port 8082) and the
"Docker Bearer Token Realm" enabled. Jenkins pushes to `localhost:8082` because Nexus runs on the
same host; machines that pull from `<host>:8082` need it in `insecure-registries` while it has no TLS.

Test results and reports are published after every run, even if a stage fails.

When a build fails, the library sends a Discord message with the job, build number, branch, commit
and build URL. The webhook URL is stored in Jenkins as a **Secret text** credential with id
`discord-webhook-url` (override it with `discordCredentialsId`). The step uses `curl`, so no extra
plugin is required. If the credential or the webhook fails, the notification is skipped and the
pipeline result is not changed.

The steps in `vars/` can also be used on their own from any Jenkinsfile that loads the library,
for example `gradlew 'build'` or `publishTestReports()`.

## Terraform plan against the S3 backend (phase 1)

Optional stage (`terraformPlan: false` by default) that runs a **real plan for
one root, on the `dev` branch only**, and keeps the saved plan in the workspace
of the same build. The plan itself never runs `apply` (that is the separate
`Terraform apply` stage below), never archives the plan and never changes the
Terraform roots.

```groovy
circleguardPipeline(
    // ...
    terraformPlan: true          // root, branch and credential come from the defaults
)
```

| Step | Image (pinned) | Commands |
|------|----------------|----------|
| `terraformPlan` | `hashicorp/terraform:1.17.2` | `terraform init -backend=true -no-color -input=false` · `terraform plan -no-color -input=false -lock=true -detailed-exitcode -out=ci-<env>.tfplan` (workdir = the root) |

### Gating

The stage runs only when **both** conditions hold: `terraformPlan` is enabled
**and** `env.BRANCH_NAME` belongs to `terraformPlanBranches` (default
`['dev']`). PR builds (`PR-*`) and every other branch never reach the stage, so
the AWS credential is never handed to code that comes from a pull request.

### Credentials

`aws-terraform-credentials` (username = Access Key ID, password = Secret Access
Key) is bound with `withCredentials()` **only** around `init` and `plan`, and the
values are passed to `runInContainer` **by name** (`envVars: [...]`), which
expands them to `-e <name>`: no value reaches a command line or the build log,
and nothing outside that block can read them. The non-secret environment
(`AWS_DEFAULT_REGION`, `TF_IN_AUTOMATION=1`, `TF_INPUT=0`,
`TF_PLUGIN_CACHE_DIR`) is scoped with `withEnv`.

### Exit codes (`-detailed-exitcode`)

| Code | Meaning | Result |
|------|---------|--------|
| `0` | plan OK, no changes | stage passes (`changes: false`) |
| `2` | plan OK, changes pending | stage passes (`changes: true`) |
| `1` | error (backend, provider, `AccessDenied`, ...) | stage fails |

On `AccessDenied` the failure message asks to **record the action and the
resource involved**: the IAM policies are never widened to make a build pass.

### The plan file

- Lives at `<root>/ci-<env>-b<build>.tfplan` (e.g.
  `infra/terraform/envs/dev/ci-dev-b47.tfplan`): **the build number is part of
  the name**, so the plan of another build cannot be applied by mistake.
- Next to it, `<plan>.info` records `build`, `commit`, `root`, `changes`,
  `status`, `sha256` and `createdAt` — the provenance that `terraformApply`
  validates. The `sha256` is computed with `sha256sum`: **without that tool the
  plan step fails closed** and leaves no sidecar. The step **returns** the same
  hash and the pipeline publishes it as **`env.TF_PLAN_SHA256`** (S2), so the
  approval step of E4 can bind an approval to the exact plan.
- It is **not archived**: it must not be downloadable, only reviewable in the
  workspace of the same build (the `Terraform apply` stage reads it from there).
- The extension is ignored by `.gitignore` (`*.tfplan`), so it can never be committed.
- The plan of a previous build (and its sidecar) is deleted (`rm -f`) before the
  run, so an old plan can never be reused.

### Reuse and guards

- Free space is checked **before** any Terraform command and **before** the
  credential is bound, reusing the parser of `terraformValidate`
  (`terraformValidate.freeSpaceMB`) and the threshold `terraformMinFreeSpaceMB`
  (1500 MB by default).
- The plugin cache is the same directory (`<workspace>/.terraform-plugin-cache`,
  `/ws/.terraform-plugin-cache` inside the container), so the ~772 MB provider
  downloaded by `init` is shared with the validate stage and never duplicated.
- The root must exist and must declare its backend in `versions.tf`; the root
  path is validated (relative, no `..`) because it is interpolated into a command.

### Known limitations and follow-ups

- **`required_version` discrepancy**: the three `versions.tf` declare
  `>= 1.6.0` while their backends use `use_lockfile = true`, which requires
  Terraform `>= 1.10`. The image is pinned to `1.17.2`, so the run works, but the
  constraint does not enforce it. **Recommendation: raise `required_version` to
  `>= 1.10` in `envs/{dev,stage,prod}/versions.tf`** — not changed in this phase.
- **Builds queue, nothing is aborted**: `circleguardPipeline` uses
  `disableConcurrentBuilds()` without `abortPrevious`, so a newer push waits for
  the running build instead of cancelling it (see *Concurrency: builds queue*
  below). A plan or an apply in progress is never interrupted by a new push.
- **IAM permissions are not validated yet**: if the first real plan reports
  `AccessDenied`, report the action and the resource. Known candidates from the
  IAM simulation are `s3:ListBucket` without `s3:prefix`, `ec2:DescribeVolumes`,
  `ec2:DescribeTags`, `ec2:DescribeVpcSecurityGroupRules` and
  `dlm:GetLifecyclePolicies`. Never widen the policies from a build failure.

## Image vulnerabilities (Trivy Image)

Optional, **off by default** (`trivyImageScan: false`). When it is enabled, every
image built by `Publish images` is scanned with Trivy **between `docker build`
and `docker push`**, so a HIGH/CRITICAL finding never reaches the registry.

```groovy
circleguardPipeline(
    // ...
    trivyImageScan: true
)
```

| Step | Image (pinned) | Command |
|------|----------------|---------|
| `trivyImageScan` | `aquasec/trivy:0.76.2` (the **tool**) | `docker run --rm … aquasec/trivy:0.76.2 image --severity HIGH,CRITICAL --exit-code 1 --pull never --format table --output trivy-image-report-<build>-<slug>.txt --cache-dir /ws/.trivy-cache [--ignorefile .trivyignore.yaml] <ref>` |

### How the local image is read

- The image is tagged in the Docker daemon of the host
  (`localhost:8082/<name>:<version>`), so the container talks to the daemon
  through a **bind mount of `/var/run/docker.sock`**, and `--pull never` stops
  Trivy from reaching `localhost:8082` from inside the container (where
  `localhost` would be the container itself).
- The workspace is mounted with the same `volume-subpath` pattern as
  `runInContainer`, so the report lands in the workspace of the job and the
  container never reaches `credentials.xml`, `secrets/` or another job's
  workspace.
- The Trivy database and cache live in `/ws/.trivy-cache`, shared with the IaC
  scan (downloaded once, scanned sequentially).
- **No credentials are needed**: the image is local and the database is public.
  The `ref`, the severity and the ignore file are validated before being put in
  a command line.

### Threshold and exceptions

- `--severity HIGH,CRITICAL --exit-code 1`: any finding blocks the build, exactly
  like the IaC scan. **No `--ignore-unfixed`.**
- Documented exceptions live in the project's `.trivyignore.yaml`
  (`vulnerabilities:` section, with `statement` and `expired_at`), the same file
  used for the IaC scan, and are passed with `--ignorefile` **only when the file
  exists**. Exceptions are decided after reviewing real results.

### Evidence

- The report `trivy-image-report-<build>-<slug>.txt` is unique per build **and**
  per image (a report of a previous build is never archived: it is removed with
  `rm -f` first), is **echoed and archived before the step fails**, and the
  failure message points to the report and to the ignore file.

### Gating and publication

- Two gates: the opt-in flag `trivyImageScan` **and** a branch in
  `trivyImageBranches` (default `['dev', 'main']`); the stage itself is already
  restricted by `publishBranches`, so **PRs neither scan nor publish**. The scan
  additionally requires `env.BRANCH_NAME` to exist **and** to be listed in
  `trivyImageBranches`: a missing or unlisted branch skips the scan (the
  publication continues without it).
- The scan runs **inside** `Publish images`: a failure skips the `push` of that
  image and the registry session is still closed (`finally`). The images pushed
  before the failing one stay in the registry — **partial publication is
  accepted**, because the version is unique to the build and the deployment needs
  every image of that version (a missing image fails at deploy time).

### Known limitations and follow-ups

- **`--pull never` has not been executed in this environment**: confirm it in the
  first real build (`trivy image --help`). If it were unsupported the failure is
  visible, and the fallback is `docker save` + `trivy image --input`.
- **The Docker socket is mounted into the pinned Trivy container** for the
  duration of the scan (root-equivalent on the host). Mitigations: the tool image
  is pinned (never `latest`) and the container is `--rm`.
- The scan adds time to the `publish` stage (40 min for 9 images) and the first
  run downloads the database (~50 MB) into the shared cache.

## Terraform apply

Optional stage (`terraformApply: false` by default) that applies **the plan
produced by the `Terraform plan` stage of the SAME build**. STAGE has no
parameters at all; the PROD stages are **implemented and wired but disabled by
default** (`terraformApplyProd`, `terraformApproval` and `terraformApprovalProd`
are all `false`), so only DEV runs unless those switches are enabled together.

```groovy
circleguardPipeline(
    // ...
    terraformPlan: true,
    terraformApply: true      // root, branch and credential come from the defaults
)
```

| Step | Image (pinned) | Commands |
|------|----------------|----------|
| `terraformApply` | `hashicorp/terraform:1.17.2` | `terraform init -backend=true -no-color -input=false` · `terraform apply -no-color -input=false -lock=true ci-<env>-b<build>.tfplan` (workdir = the root) |

### Provenance: only the plan of this build

The plan is named **`ci-<env>-b<build>.tfplan`** and `terraformPlan` writes a
sidecar **`<plan>.info`** with `build`, `commit`, `root`, `changes`, `status`
and `createdAt`. The plan stage also publishes `env.TF_PLAN_BUILD`,
`env.TF_PLAN_ROOT`, `env.TF_PLAN_FILE`, `env.TF_PLAN_INFO`,
`env.TF_PLAN_SHA256` (the hash the approval step of E4 binds to; `terraformApply`
still validates it from the sidecar and by recomputing it) and
`env.TF_PLAN_CHANGES`. Before running anything, `terraformApply` verifies:

1. `env.TF_PLAN_BUILD` exists and equals `env.BUILD_NUMBER`;
2. `env.TF_PLAN_ROOT`, `env.TF_PLAN_FILE` and `env.TF_PLAN_INFO` match the target;
3. `env.TF_PLAN_CHANGES` is `true`/`false` and matches the sidecar;
4. `env.GIT_COMMIT` exists and equals the sidecar's `commit`;
5. the plan file and the sidecar exist;
6. the `<plan>.applied` marker does **not** exist (the same plan is never applied twice);
7. the sidecar's `status` is coherent with `changes` (`2` ⇔ `true`, `0` ⇔ `false`);
8. the sidecar's `sha256` equals the SHA-256 recomputed with `sha256sum`
   (**fail closed**: if `sha256sum` is missing or the hash differs, nothing is applied).

**Every inconsistency fails with `error` BEFORE any Terraform command.**

### Commands and guards

- `init -backend=true` (idempotent) and `apply -lock=true` only. **Never**
  `-lock=false`, `-auto-approve`, `-destroy`, `-replace`, `-reconfigure` or
  `-migrate-state`.
- `aws-terraform-credentials` is bound with `withCredentials` only around those
  two commands and passed **by name**: no value reaches a command line or the log.
- **No Terraform output is echoed**; the archived evidence
  (`terraform-apply-<env>-b<build>.txt`) only contains build, branch, commit,
  root, plan, changes, outcome and date — no credential, no output.
- On failure the **original exception is rethrown unchanged**; the `AccessDenied`
  guidance (record the action and the resource; never widen the IAM policies) is
  echoed **only when the failure really is an `AccessDenied`** — never for an
  interruption (timeout or abort).

### No changes, ordering and evidence

- If the plan reported no changes: `SKIPPED_NO_CHANGES` is registered and
  **`init`/`apply` are omitted** (no AWS call, no lock).
- After a successful apply, in this order and **without any automatic retry**:
  1. the `<plan>.applied` marker,
  2. the evidence (written and archived),
  3. `rm` of the plan and its sidecar.
  If step 2 or 3 fails, the step reports explicitly that **the apply SUCCEEDED**
  and that the build must not be re-run blindly — the marker, written first,
  stops a second apply of the same plan.
- Stage budget: `terraformApplyTimeout * 2` minutes (init + apply), while each
  command gets `terraformApplyTimeout`.

### PROD target and approval (S5)

The pipeline resolves a **fixed target per branch** (`terraformTarget()`), so a
branch and a root can never be combined arbitrarily:

| Branch | Target | Plan root | Apply |
|--------|--------|-----------|-------|
| `dev` (in `terraformApplyBranches`) | DEV | `terraformPlanRoot` | `terraformApplyRoot`, **no approval** |
| `main` (in `terraformApplyProdBranches`) | PROD | `terraformApplyProdRoot` | `terraformApplyProdRoot`, **approval required** |
| PR / any other branch | none | — | — |

- A branch configured for **both** lists, or a PROD target selected from a branch
  other than `main`, **fails the build** (`terraformTarget()`).
- Stages: `Terraform plan PROD` → `Terraform approval` → `Terraform apply PROD`,
  between the DEV plan and `Publish images`.
- **Gates (all required):** plan `terraformApplyProd` **and** `terraformPlan` +
  PROD target · approval `terraformApplyProd` **and** `terraformApproval`
  **and** `terraformApprovalProd` + PROD target + plan with changes · apply
  `terraformApplyProd` + PROD target + plan with changes **and**
  `TF_APPROVED_TARGET == 'prod'` (otherwise it refuses explicitly, before any
  credential). The apply step receives `requireApproval: true` and
  `maxAgeMinutes: terraformApprovalMaxAgeMinutes` and re-validates build, commit,
  root, both hashes and both ages (S3/S4).
- **All PROD switches are OFF by default** (`terraformApplyProd`,
  `terraformApproval`, `terraformApprovalProd`): nothing runs until they are
  enabled together, and the `Jenkinsfile` was not changed.
- **Remaining budget guard:** before showing the `input`, the stage calls
  **`requireApprovalTimeLeft()`**, which computes the time left of the whole
  build with a plain `System.currentTimeMillis()` anchored at the start of
  `call()` and compares it with `terraformApprovalTimeout`; if less than a full
  window is left it fails **without showing the input and without applying**. The anchor is never later
  than the start of the global `timeout(time: pipelineTimeoutMinutes)` (120 min,
  single source of truth), so the value is conservative: it can refuse early,
  never late. `currentBuild.duration` / `currentBuild.rawBuild` were rejected
  (liveness and deprecation are not verifiable without a real Jenkins run).

### Concurrency: builds queue

`circleguardPipeline` uses **`disableConcurrentBuilds()`**; the `abortPrevious`
option is **not** used. When a new build of the same branch starts while another
one is running, the new build **waits in the queue** instead of aborting the
running one. The aborting behaviour was removed because a build inside
`terraform apply` (or waiting for a manual approval) could be killed mid-write
and leave the `.tflock` object in S3, with a state to review.

Operational implications:

- A running `terraform apply` or a pending approval **always runs to completion**:
  no newer push can cancel it.
- Pushes **accumulate in the queue** instead of cancelling the older builds: after
  a long stage (an approval waits up to `approvalTimeout` = 240 minutes) several
  queued builds may run one after another. Every queued build produces its own
  plan (its own build number), so a plan is never reused across builds.
- Builds are **no longer cancelled automatically**: a stale queued build still
  runs when its turn comes. If one must be discarded, stop it manually — never by
  re-enabling `abortPrevious` without an explicit approval.
- The `timeout` of 120 minutes applies **per build**, not to the whole queue.
- The same limit caps the **image promotion**: `approvalTimeout` (240 min) is the
  maximum the approver is allowed to take, but the build stops 120 minutes after
  it started, so the effective waiting time for `Promote to prod` is
  `120 min − elapsed`. The Terraform approval (`terraformApprovalTimeout`, 30 min)
  fits inside that budget and is additionally guarded by `requireApprovalTimeLeft()`.
- The `.tflock` recovery runbook still applies to other interruptions (stage
  timeout, manual abort): delete the object only after confirming that no build is
  running.

### Known limitations and follow-ups

- **STAGE has no parameters at all; PROD is implemented and wired but disabled
  by default**: `terraformApplyProdRoot`, `terraformApplyProdBranches`,
  `terraformApplyProd`, `terraformApproval` and `terraformApprovalProd` exist
  with safe defaults (**every switch off**) and the three PROD stages
  (`Terraform plan PROD`, `Terraform approval`, `Terraform apply PROD`) are
  gated by them, so **no PROD stage is selected on any branch** with the
  defaults. STAGE would still need new parameters.
- **The approval step is wired**: `terraformApproval` is invoked by the
  `Terraform approval` stage, between the PROD plan and the PROD apply, and its
  configuration (`terraformApprovalTimeout = 30`,
  `terraformApprovalSubmitter = 'admin'`, `terraformApprovalMaxAgeMinutes = 60`)
  is validated when the pipeline is built — timeout and max age must be `> 0`
  and the submitter must not be empty. Those settings have no effect while the
  PROD switches stay off.
- **What the approval step checks**: `vars/terraformApproval.groovy` validates the
  plan (build, commit, root, both hashes and its age, including
  `createdAt <= approvedAt`) **before** asking for the `input`, and only then
  persists `TF_APPROVED_BY`, `TF_APPROVED_AT`, `TF_APPROVED_PLAN_SHA` and
  `TF_APPROVED_BUILD`; `terraformApply` re-validates all of it **before binding
  any credential**. Those settings have no effect while the PROD switches stay
  off.
- `GIT_COMMIT` is **required**: without it the provenance check fails closed.
- Plans of previous builds (`ci-<env>-b<*>.tfplan`) remain in the `dev`/`main`
  workspaces; they can never be applied (the name carries another build number)
  and could be cleaned up in a later phase.
- The permissions of a real `apply` are still unvalidated: on `AccessDenied`
  record the action and the resource and report them; never widen the IAM
  policies from a build failure.

## Registering the library in Jenkins

**Manage Jenkins → System → Global Trusted Pipeline Libraries**

- Name: `circleguard-pipeline-library`
- Default version: `main`
- Allow default version to be overridden: yes
- Retrieval method: Modern SCM → Git → `https://github.com/isabellacv1/circleguard-jenkins-library.git`

Or with Configuration as Code (`jenkins.yaml`, under `unclassified`):

```yaml
globalLibraries:
  libraries:
  - name: "circleguard-pipeline-library"
    defaultVersion: "main"
    allowVersionOverride: true
    implicit: false
    retriever:
      modernSCM:
        scm:
          git:
            remote: "https://github.com/isabellacv1/circleguard-jenkins-library.git"
```

## Post-deployment smoke tests (HU-15)

After `Verify deployment`, the `Smoke tests` stage runs `smokeTests()` against the deployed environment.
The same checks run after every promotion (stage, prod).

| Check | Request | Expected |
|-------|---------|----------|
| web home page | `GET :8081/` | 200 and HTML |
| web runtime configuration | `GET :8081/env-config.js` | 200 and `__ENV__` |
| gateway validates a token | `POST :8087/api/v1/gate/validate` | 200 and a validation result |
| form lists pending surveys | `GET :8086/api/v1/certificates/pending` | 200 |
| promotion health stats | `GET :8088/api/v1/health-status/stats` | 200 and JSON |
| identity requires auth | `GET :8083/api/v1/identities/lookup/<id>` without token | 401 or 403 |
| auth login with valid user | `POST :8180/api/v1/auth/login` (credential `e2e-credential`) | 200 and a token |
| auth rejects a wrong password | `POST :8180/api/v1/auth/login` | 401 |

- Every check expects a specific status (and body fragment), unlike `verifyServices`, which accepts any answer below 500.
- The checks run on the target host over SSH against `localhost`, so the application ports do not need to be open to Jenkins.
- Results: JUnit report `smoke-tests/smoke-<env>.xml` (Tests tab) and `smoke-tests/smoke-<env>.txt` (artifact).
- If a check fails, the build fails and its description says `smoke tests FAILED on <env>`.

| Parameter | Default | Description |
|-----------|---------|-------------|
| `smokeTests` | `true` | Runs the smoke tests after the deployment and after each promotion. |
| `smokeCredentialsId` | `e2e-credential` | Username/password credential for the login check (`null` skips the login checks). |
| `smokeTimeout` | `10` | Smoke tests stage timeout (minutes). |

## Disk cleanup on the Jenkins host

`dockerCleanup()` runs before building the images and at the end of every build (`dockerCleanup: true`).
It removes BuildKit cache above 2 GB, dangling images, stopped containers and unused anonymous volumes
left by Testcontainers. It never touches running containers, images in use or named volumes, and it
never fails the build. The disk before and after is printed in the log.

At the end of PR and feature branch builds the workspace is deleted (`deleteDir()`); `dev` and `main` keep
theirs so the next build is faster.
