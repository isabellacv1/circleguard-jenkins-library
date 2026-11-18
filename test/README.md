# Tests of the library

Behavioural tests for the reusable steps. They are **unit tests**: every Jenkins
step (`sh`, `echo`, `error`, `env`, `fileExists`, `readFile`, `archiveArtifacts`,
`withEnv`, `withCredentials`, `usernamePassword`, `timeout`) is replaced by an
in-memory stub, so the tests need

- **no Docker image** (nothing is downloaded),
- **no network**,
- **no AWS credentials** and no Terraform/Trivy binary installed.

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
| `terraformPlan` | `init -backend=true` (**never** `-backend=false`, `-reconfigure` or `-migrate-state`) + `plan -no-color -input=false -lock=true -detailed-exitcode -out=ci-<env>.tfplan`, **credential bound exactly once** with id `aws-terraform-credentials` and variables `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`, env vars passed **by name only** (no value, no interpolation), `AWS_DEFAULT_REGION`/`TF_IN_AUTOMATION`/`TF_INPUT`/`TF_PLUGIN_CACHE_DIR` via `withEnv`, exit codes **0 / 2 / 1** interpreted (`changes` flag, failure message with the AccessDenied rule), plan **never archived**, stale plan removed first, free-space gate **before** the credential is bound (parser reused from `terraformValidate`), fail-fast on a missing root / missing `versions.tf` / unsafe root path / plan name without `.tfplan` / empty credential id, **no apply step exists** |
| `PipelineConfig` | new stages **off by default**, pinned images, **DEV-only** default roots, `terraformMinFreeSpaceMB` default, parameters accepted from the Jenkinsfile, **`terraformPlan` off by default** with `terraformPlanRoot` = DEV, `terraformPlanBranches` = `['dev']`, `terraformAwsCredentialsId` and `terraformAwsRegion` defaults |
| `circleguardPipeline` | compiles, declares the new stages before `Publish images`, gates them with `cfg.terraformValidate` / `cfg.trivyScan`, passes the free-space threshold, keeps every pre-existing stage, `runE2E` untouched, **`Terraform plan` between `Trivy IaC` and `Publish images` gated by flag AND branch (`cfg.terraformPlanBranches`)**, no apply stage |
