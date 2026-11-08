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

### Stages

| Stage | What it does |
|-------|--------------|
| Checkout | `checkout scm` |
| Build | `./gradlew assemble` |
| Tests | `./gradlew test --continue` |
| Integration tests | `./gradlew integrationTest --continue` (if `integrationTests`) |
| SonarQube | analysis + quality gate (if `sonar`) |

Test results and reports are published after every run, even if a stage fails.

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
