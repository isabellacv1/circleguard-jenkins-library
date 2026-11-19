# Tests of the library

Behavioural tests for the reusable steps. They are **unit tests**: every Jenkins
step (`sh`, `echo`, `error`, `env`, `fileExists`, `readFile`, `archiveArtifacts`,
`junit`, `withEnv`, `withCredentials`, `usernamePassword`, `timeout`) is replaced
by an in-memory stub, so the tests need

- **no Docker image** (nothing is downloaded),
- **no network**,
- **no AWS credentials** and no Terraform/Trivy binary installed.

The sibling steps called by a step (`runInContainer`, `terraformValidate`,
`ensureBuildx`, `dockerCleanup`, `trivyImageScan`) are stubbed too; the ones used
to assert an execution order are also recorded in `trace` (in the same sequence
as the `sh` commands) and everything written with `writeFile` is recorded in
`written` (file → content). `opts.failShContains` and
`opts.failWriteFileContains` make **one** command or **one** file fail, so the
failure paths of a single step can be tested without breaking the others.

## Why `test/` and not `src/`

Jenkins loads `src/` and `vars/` when the library is used by a build. These
files must never reach the runtime of a pipeline, so they live outside both
directories and are only executed by hand (or by a future CI job of this
repository).

## Running them

They only need a Groovy runtime (any Groovy 3/4/5 works; Groovy is already in
the Gradle caches of the developer machines, so nothing has to be installed):

```bash
# from the root of the library
java -cp "$(find ~/.gradle -name 'groovy-5*.jar' | head -1)" \
     groovy.ui.GroovyMain test/StepTests.groovy

# or passing the root of the library explicitly
java -cp <groovy.jar> groovy.ui.GroovyMain test/StepTests.groovy /path/to/circleguard-jenkins-library
```

Exit code `0` means all tests passed; `1` reports the failing ones.

## What is covered

| Area | Checks |
|------|--------|
| `runInContainer` | mount limited to the job with `volume-subpath` (no whole volume, no host path), **`--mount` tokenised separately from its value** (regression for `unknown flag: --mount type`), `--user`/`HOME`, env vars passed **by name only**, rejection of a workspace outside `/var/jenkins_home/workspace` and of a workspace that does not exist yet, rejection of `:latest` and untagged images, missing workspace/command, `returnStatus` |
| `terraformValidate` | free-space check **first** (`df -Pk`) and abort with the available/threshold message before any Terraform command, creation of the plugin cache, `TF_PLUGIN_CACHE_DIR` passed by name and scoped with `withEnv`, `fmt -check` + `init -backend=false` + `validate` per root, **never** `plan`/`apply`/`destroy`/`-upgrade`, no AWS credentials, fail-fast on a missing root |
| `trivyScan` | `trivy config`, `--severity HIGH,CRITICAL`, `--exit-code 1`, cache in the workspace (`/ws/.trivy-cache`) and never shared, exclusions of `.terraform`/`.trivy-cache`/`*.tfstate*`/`*.tfplan*`, report per build (`trivy-iac-report-<build>.txt`) echoed and archived, **previous build report never archived**, correct message when no report was generated, blocking on findings with the evidence kept, `--ignorefile` only when the file exists, one target per invocation |
| `terraformPlan` | `init -backend=true` (**never** `-backend=false`, `-reconfigure` or `-migrate-state`) + `plan -no-color -input=false -lock=true -detailed-exitcode -out=ci-<env>-b<build>.tfplan` + sidecar `<plan>.info` (build, commit, root, changes, status, sha256, date; `sha256sum` **fail closed**), **credential bound exactly once** with id `aws-terraform-credentials` and variables `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`, env vars passed **by name only** (no value, no interpolation), `AWS_DEFAULT_REGION`/`TF_IN_AUTOMATION`/`TF_INPUT`/`TF_PLUGIN_CACHE_DIR` via `withEnv`, exit codes **0 / 2 / 1** interpreted (`changes` flag, failure message with the AccessDenied rule), plan **never archived**, stale plan removed first, free-space gate **before** the credential is bound (parser reused from `terraformValidate`), fail-fast on a missing root / missing `versions.tf` / unsafe root path / plan name without `.tfplan` / empty credential id, plan **never applied by this step** |
| `terraformApply` | **provenance before anything**: `TF_PLAN_BUILD == BUILD_NUMBER`, `TF_PLAN_ROOT`/`TF_PLAN_FILE`/`TF_PLAN_INFO` match, `TF_PLAN_CHANGES` valid and equal to the sidecar, `GIT_COMMIT` equals the sidecar, `status` coherent with `changes` (`2` ⇔ `true`), `sha256` recomputed with `sha256sum` and compared with the sidecar (**fail closed** if the tool is missing or the hash differs), plan + sidecar exist, `.applied` marker absent → each failure runs with **`sh` empty**; `SKIPPED_NO_CHANGES` registers the outcome and omits `init`/`apply` (no credential, no lock); with changes: `df` → `sha256sum` → `mkdir` → `init -backend=true` → **`apply -lock=true <plan>`** (never `-lock=false`, `-auto-approve`, `-destroy`, `-replace`, no `terraform output`), credential bound once by name, order **marker → evidence → cleanup**, evidence with `Outcome: APPLIED`/`SKIPPED_NO_CHANGES` archived (no credential, no output), original failure **rethrown unchanged** with the AccessDenied guidance **only for an AccessDenied** (`failShMessage`), and explicit, non-retried messages that say the infrastructure may have changed: `INFRASTRUCTURE MAY HAVE CHANGED` + `could NOT be written` vs `WAS written … could NOT be archived` vs the cleanup (`failWriteFileContains` / `failArchiveContains` / `failShContains`, no `retry(`) |
| `runE2E` | mount limited to the job with **`volume-subpath`** (never `-v <volume>:` and never a host path), `--mount` tokenised separately from its value, `-w /jh/tests/e2e-playwright`, `--user`/`HOME`, credentials bound once with `E2E_USERNAME`/`E2E_PASSWORD` **by name**, Playwright command and pinned image kept, **reports published in `finally` even when the container fails**, rejection of a workspace outside `/var/jenkins_home/workspace` and of a workspace that does not exist yet (nothing runs), no step mounts the whole volume anymore |
| `trivyImageScan` | `docker run` with **both mounts tokenised separately** (workspace `volume-subpath` + `type=bind` of `/var/run/docker.sock`), pinned tool image, `image --severity HIGH,CRITICAL --exit-code 1 --pull never`, `--cache-dir /ws/.trivy-cache`, `--ignorefile` only when the file exists, report `trivy-image-report-<build>-<slug>.txt` echoed **and archived before failing**, previous build's report never archived, **exit 0 vs findings vs scan error** (no report), guards (missing/invalid `ref`, unpinned tool image, ignore file outside the workspace, unsafe workspace, missing workspace → nothing runs), no `push` and no registry/AWS credential in the command |
| `publishImages` | `ensureBuildx` → `dockerCleanup` → `login` → **`build` → `scan` → `push` → `rm` → `logout`** (order asserted through `trace`), scan **off by default**, gated by `scanBranches` **and a known `BRANCH_NAME`** (a missing or unlisted branch skips the scan), **a failing scan skips the `push`, keeps the image and still logs out**, no `published-images.txt` on failure |
| `PipelineConfig` | new stages **off by default**, pinned images, **DEV-only** default roots, `terraformMinFreeSpaceMB` default, parameters accepted from the Jenkinsfile, **`terraformPlan` off by default** with `terraformPlanRoot` = DEV, `terraformPlanBranches` = `['dev']`, `terraformAwsCredentialsId` and `terraformAwsRegion` defaults |
| `circleguardPipeline` | compiles, declares the new stages before `Publish images`, gates them with `cfg.terraformValidate` / `cfg.trivyScan`, passes the free-space threshold, keeps every pre-existing stage, `runE2E` stage untouched, **`Terraform plan` between `Trivy IaC` and `Publish images` gated by flag AND branch (`cfg.terraformPlanBranches`)**, **persists the plan result in `env.TF_PLAN_BUILD/ROOT/FILE/INFO/CHANGES`**, **`Terraform apply` right after the plan and before `Publish images`** (flag AND branch, stage budget `2 × cfg.terraformApplyTimeout`), **passes the Trivy Image configuration (`cfg.trivyImageScan`, `cfg.trivyImage`, `cfg.trivyImageSeverity`, `cfg.trivyImageBranches`, `cfg.trivyImageTimeout`, `cfg.trivyImageIgnoreFile`) to `publishImages`, whose stage keeps the `publishBranches` gate** |
