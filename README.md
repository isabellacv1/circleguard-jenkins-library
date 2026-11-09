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
| `approvalTimeout` | `240` | Minutes the approver has to answer the `input`. |
| `promotionRecordFile` | `promotion-record.txt` | Artifact with the evidence of every promotion. |

### Stages

| Stage | What it does |
|-------|--------------|
| Checkout | `checkout scm` |
| Build | `./gradlew assemble` |
| Tests | `./gradlew test --continue` |
| Integration tests | `./gradlew integrationTest --continue` (if `integrationTests`) |
| SonarQube | analysis + quality gate (if `sonar`) |
| Publish images | `docker build` + `docker push` of every image (if `publish` and branch in `publishBranches`) |
| Deploy | Copies the compose files to the target host over SSH and runs `docker compose up -d --wait` with the published images (if `deploy` and branch in `deployBranches`) |
| Verify deployment | HTTP check of every component with retries; the build fails if a service does not answer (if `deploy`) |
| E2E tests | Playwright tests in a container against the deployed `dev` (condition to promote, if `e2e`) |
| Promote to stage | Deploys the **same version** to `stage` and verifies it; manual `input` only if `stageApproval` |
| Promote to prod | Deploys the **same version** to `prod`, verifies it and archives `promotion-record.txt`; always behind a manual `input` |

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
