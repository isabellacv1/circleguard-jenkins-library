/**
 * Unit / behaviour tests for the Terraform and Trivy steps of the library.
 *
 * They run WITHOUT Docker, WITHOUT network and WITHOUT AWS credentials: every
 * Jenkins step (sh, echo, error, env, fileExists, readFile, archiveArtifacts,
 * withEnv, timeout) is replaced by an in-memory stub, so only the logic of the
 * steps is exercised (mounts, command construction, validations, blocking
 * behaviour, evidence).
 *
 * Run from the root of the library:
 *
 *   java -cp <groovy.jar> groovy.ui.GroovyMain test/StepTests.groovy
 *   java -cp <groovy.jar> groovy.ui.GroovyMain test/StepTests.groovy /path/to/library
 *
 * Exit code: 0 = all tests passed, 1 = at least one failure.
 *
 * The tests live in test/ (not in src/) on purpose: Jenkins compiles src/ and
 * vars/, and these files must never be loaded by the runtime of a build.
 */

File root = new File(args.length > 0 ? args[0] : '.')
if (!new File(root, 'vars').isDirectory()) {
    System.err.println "ERROR: '${root}' is not the root of the library (vars/ not found)"
    System.exit(2)
}

// `df -Pk` output with plenty of space (4000000 KB = 3906 MB) and with almost none
// (100000 KB = 97 MB), used to exercise the free-space gate of terraformValidate.
String ENOUGH_DF = '''Filesystem 1024-blocks    Used Available Capacity Mounted on
/dev/root        28000000 24000000   4000000      86% /'''
String LOW_DF = '''Filesystem 1024-blocks    Used Available Capacity Mounted on
/dev/root        28000000 27900000    100000      97% /'''

int passed = 0
List<String> failures = []

def test = { String name, Closure body ->
    try {
        body()
        passed++
        println "  PASS  ${name}"
    } catch (Throwable t) {
        String message = t.message ?: t.class.name
        failures << "${name}: ${message}"
        println "  FAIL  ${name}: ${message}"
    }
}

GroovyClassLoader loader = new GroovyClassLoader(this.class.classLoader)

// Parsed once: terraformPlan reuses the free-space parser of terraformValidate
// (terraformValidate.freeSpaceMB), so the real step must be bindable.
def validateTemplate = loader.parseClass(new File(root, 'vars/terraformValidate.groovy'))

/**
 * Splits a shell command into argv tokens, honouring single/double quotes and
 * keeping `$( ... )` substitutions in one token. Used to reproduce what the
 * `sh` step of Jenkins really passes to `docker`.
 */
def tokenizeShell = { String s ->
    List<String> tokens = []
    StringBuilder cur = new StringBuilder()
    boolean single = false
    boolean dbl = false
    int i = 0
    while (i < s.length()) {
        char c = s.charAt(i)
        if (!single && !dbl && c == ('$' as char) && i + 1 < s.length() && s.charAt(i + 1) == ('(' as char)) {
            int depth = 1
            cur.append('$(')
            i += 2
            while (i < s.length() && depth > 0) {
                char cc = s.charAt(i)
                if (cc == ('(' as char)) { depth++ }
                else if (cc == (')' as char)) { depth-- }
                cur.append(cc)
                i++
            }
            continue
        }
        if (c == ("'" as char) && !dbl) { single = !single; i++; continue }
        if (c == ('"' as char) && !single) { dbl = !dbl; i++; continue }
        if (Character.isWhitespace(c) && !single && !dbl) {
            if (cur.length() > 0) { tokens << cur.toString(); cur.setLength(0) }
            i++; continue
        }
        cur.append(c)
        i++
    }
    if (cur.length() > 0) { tokens << cur.toString() }
    tokens
}

/**
 * Instantiates a step with a stubbed Jenkins environment.
 *
 * Returns a map with: script, sh (recorded commands), logs, archived, withEnv,
 * withCredentials (the bindings recorded by the stubbed withCredentials).
 * opts.status     exit code returned by sh(..., returnStatus: true)
 * opts.missing    paths for which fileExists() answers false
 * opts.files      contents returned by readFile()
 * opts.dfOutput   stdout of the `df` call (free-space check)
 */
def newStep = { String name, Map opts = [:] ->
    def script = loader.parseClass(new File(root, "vars/${name}.groovy")).newInstance()
    Map b = [
        env     : (opts.containsKey('env') ? opts.env :
                   [WORKSPACE: '/var/jenkins_home/workspace/circleguard_dev',
                    BUILD_NUMBER: '42']),
        sh      : [],
        logs    : [],
        archived: [],
        withEnv : [],
        withCredentials: []
    ]
    def binding = new Binding()
    binding.setVariable('env', b.env)
    binding.setVariable('echo', { Object m -> b.logs << m.toString() })
    binding.setVariable('error', { Object m -> throw new RuntimeException(m.toString()) })
    binding.setVariable('sh', { Object arg ->
        if (arg instanceof Map) {
            String scriptText = arg.script.toString()
            b.sh << scriptText
            if (arg.returnStatus) {
                return (opts.status ?: 0) as int
            }
            if (arg.returnStdout) {
                if (scriptText.startsWith('df ')) {
                    return (opts.dfOutput ?: ENOUGH_DF)
                }
                return (opts.stdout ?: '')
            }
            return 0
        }
        b.sh << arg.toString()
        return 0
    })
    binding.setVariable('withEnv', { Object vars, Closure body ->
        // toString(): the pipeline passes GStrings, and List.contains(String)
        // would never match a GString element
        b.withEnv << (vars.collect { it.toString() })
        return body.call()
    })
    // withCredentials records the bindings, runs the body and returns its value,
    // like the real step; usernamePassword() returns its arguments, so a test can
    // assert the credential id and the variable names WITHOUT reading any secret.
    binding.setVariable('usernamePassword', { Object args -> args })
    binding.setVariable('withCredentials', { Object bindings, Closure body ->
        b.withCredentials << bindings
        return body.call()
    })
    // terraformPlan reuses the free-space parser of terraformValidate: the real
    // step is bound so that terraformValidate.freeSpaceMB() is the production one.
    def validate = validateTemplate.newInstance()
    validate.binding = binding
    binding.setVariable('terraformValidate', validate)
    binding.setVariable('fileExists', { Object p -> !(opts.missing ?: []).contains(p) })
    binding.setVariable('readFile', { Object p -> (opts.files ?: [:])[p] ?: "REPORT:${p}" })
    binding.setVariable('writeFile', { Object a -> })
    binding.setVariable('archiveArtifacts', { Object a ->
        b.archived << (a instanceof Map ? a.artifacts : a.toString())
    })
    binding.setVariable('timeout', { Object o, Closure c -> c.call() })
    script.binding = binding

    // Steps call other steps through the same binding (runInContainer).
    def container = loader.parseClass(new File(root, 'vars/runInContainer.groovy')).newInstance()
    container.binding = binding
    binding.setVariable('runInContainer', { Map p -> container.call(p) })

    [script: script, sh: b.sh, logs: b.logs, archived: b.archived,
     withEnv: b.withEnv, withCredentials: b.withCredentials]
}

println 'runInContainer'
test('builds a docker run command bound to the job workspace only') {
    def h = newStep('runInContainer')
    h.script.call(image: 'hashicorp/terraform:1.17.2',
                  command: 'fmt -check -recursive -no-color infra/terraform',
                  envVars: ['AWS_REGION'])
    assert h.sh.size() == 1
    String cmd = h.sh[0]
    assert cmd.startsWith('docker run --rm')
    assert cmd.contains('--user $(id -u):$(id -g)')
    assert cmd.contains('-e HOME=/tmp')
    // H1: only the subdirectory of the job is mounted, through volume-subpath
    assert cmd.contains("--mount 'type=volume,source=circleguard-jenkins-home," +
                        "destination=/ws,volume-subpath=workspace/circleguard_dev'")
    assert cmd.contains("-w '/ws'")
    // ... the whole volume is NOT exposed and no host path is used
    assert !cmd.contains('-v circleguard-jenkins-home')
    assert !cmd.contains('/var/lib/docker')
    assert cmd.contains('-e AWS_REGION')
    // the value of the variable must never be part of the command
    assert !cmd.contains('-e AWS_REGION=')
    assert cmd.endsWith('hashicorp/terraform:1.17.2 fmt -check -recursive -no-color infra/terraform')
}

test('translates the workdir inside the workspace mount') {
    def h = newStep('runInContainer')
    h.script.call(image: 'aquasec/trivy:0.76.2', command: 'config infra/terraform',
                  workDir: 'infra/terraform/envs/dev')
    assert h.sh[0].contains("-w '/ws/infra/terraform/envs/dev'")
    assert h.sh[0].contains('volume-subpath=workspace/circleguard_dev')
}

test('splits --mount from its value when the shell tokenizes the command') {
    // Regression: quoting the flag together with its value made the shell pass
    // "--mount type=..." as ONE argument, and the Docker CLI failed with
    // `unknown flag: --mount type` (pflag reads the flag name as "mount type").
    def h = newStep('runInContainer')
    h.script.call(image: 'hashicorp/terraform:1.17.2', command: 'fmt -check')
    List<String> tokens = tokenizeShell(h.sh[0])

    int mount = tokens.indexOf('--mount')
    assert mount > 0: "--mount must be its own token: ${tokens}"
    assert !tokens.any { it.startsWith('--mount ') }: "the flag must not carry its value: ${tokens}"
    assert tokens[mount + 1].startsWith('type=volume,'): tokens[mount + 1]
    assert tokens[mount + 1].contains('source=circleguard-jenkins-home'): tokens[mount + 1]
    assert tokens[mount + 1].contains('volume-subpath=workspace/circleguard_dev'): tokens[mount + 1]

    // -w and its value must also be separate tokens
    int w = tokens.indexOf('-w')
    assert w > 0 && tokens[w + 1] == '/ws': "wrong -w tokenisation: ${tokens}"
    // the image and its command remain separate
    assert tokens.contains('hashicorp/terraform:1.17.2')
    assert tokens.last() == 'fmt -check' || tokens[-2..-1].join(' ') == 'fmt -check'
}

test('refuses a workspace outside /var/jenkins_home/workspace') {
    def h = newStep('runInContainer', [env: [WORKSPACE: '/var/jenkins_home/secrets',
                                             BUILD_NUMBER: '42']])
    try {
        h.script.call(image: 'aquasec/trivy:0.76.2', command: 'config .')
        assert false: 'a workspace outside workspace/ must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('not under /var/jenkins_home/workspace')
    }
    assert h.sh.isEmpty(): 'nothing must run when the workspace is not isolated'
}

test('refuses to mount a workspace that does not exist yet') {
    String ghost = '/var/jenkins_home/workspace/circleguard_ghost'
    def h = newStep('runInContainer', [env: [WORKSPACE: ghost, BUILD_NUMBER: '42'],
                                       missing: [ghost]])
    try {
        h.script.call(image: 'aquasec/trivy:0.76.2', command: 'config .')
        assert false: 'a missing workspace must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('does not exist yet')
    }
    assert h.sh.isEmpty(): 'the container must not start with a missing subpath'
}

test('rejects :latest and untagged images') {
    def latest = newStep('runInContainer')
    try {
        latest.script.call(image: 'aquasec/trivy:latest', command: 'config .')
        assert false: 'latest image must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('pinned')
    }

    def untagged = newStep('runInContainer')
    try {
        untagged.script.call(image: 'aquasec/trivy', command: 'config .')
        assert false: 'untagged image must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('pinned')
    }
}

test('fails without a workspace and without a command') {
    def noWs = newStep('runInContainer', [env: [:]])
    try {
        noWs.script.call(image: 'aquasec/trivy:0.76.2', command: 'config .')
        assert false: 'missing workspace must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('no workspace available')
    }

    def noCmd = newStep('runInContainer')
    try {
        noCmd.script.call(image: 'aquasec/trivy:0.76.2')
        assert false: 'missing command must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('command is required')
    }
}

test('returns the exit status when returnStatus is requested') {
    def h = newStep('runInContainer', [status: 1])
    int status = h.script.call(image: 'aquasec/trivy:0.76.2',
                               command: 'config infra/terraform --exit-code 1',
                               returnStatus: true)
    assert status == 1
    assert h.sh.size() == 1
}

println 'terraformValidate'
test('checks the disk, creates the plugin cache and runs fmt/init/validate, and nothing else') {
    def h = newStep('terraformValidate')
    h.script.call(roots: ['infra/terraform/envs/dev'], fmtPath: 'infra/terraform')

    // df (free space) + mkdir (plugin cache) + 3 docker runs
    assert h.sh.size() == 5: "expected 5 commands, got ${h.sh.size()}"
    assert h.sh[0].startsWith('df -Pk'): 'the disk must be checked first'
    assert h.sh[1].contains('.terraform-plugin-cache'): 'the plugin cache must be created'
    assert h.sh[1].contains('/var/jenkins_home/workspace/circleguard_dev/')

    assert h.sh[2].contains(' fmt -check -recursive -no-color infra/terraform')
    assert h.sh[3].contains(' init -backend=false -no-color')
    assert h.sh[3].contains("-w '/ws/infra/terraform/envs/dev'")
    assert h.sh[3].contains('-e TF_PLUGIN_CACHE_DIR')
    assert h.sh[4].contains(' validate -no-color')
    assert h.sh[4].contains("-w '/ws/infra/terraform/envs/dev'")

    // no terraform command may run before the disk check
    assert !h.sh[0].contains('docker run')

    h.sh.findAll { it.contains('docker run') }.each { String cmd ->
        assert !cmd.contains(' plan '): "plan must never run: ${cmd}"
        assert !cmd.contains(' apply'): "apply must never run: ${cmd}"
        assert !cmd.contains(' destroy'): "destroy must never run: ${cmd}"
        assert !cmd.contains('-upgrade'): "the lockfile must not be upgraded: ${cmd}"
        assert !cmd.contains('-e AWS_'): "no AWS credentials are needed: ${cmd}"
        assert !cmd.contains('-var '): "variables are never injected: ${cmd}"
        // the cache path is passed by NAME, its value never reaches the command line
        assert !cmd.contains('TF_PLUGIN_CACHE_DIR=/'): "the value must not be in the command: ${cmd}"
    }
    assert h.sh.count { it.contains('-backend=false') } == 1
}

test('passes TF_PLUGIN_CACHE_DIR scoped with withEnv') {
    def h = newStep('terraformValidate')
    h.script.call(roots: ['infra/terraform/envs/dev'], fmtPath: 'infra/terraform')
    assert h.withEnv.size() == 1: 'the cache variable must be scoped to the init step'
    assert h.withEnv.flatten().contains('TF_PLUGIN_CACHE_DIR=/ws/.terraform-plugin-cache')
}

test('aborts before running Terraform when the disk is full') {
    def h = newStep('terraformValidate', [dfOutput: LOW_DF])
    try {
        h.script.call(roots: ['infra/terraform/envs/dev'], fmtPath: 'infra/terraform')
        assert false: 'an insufficient disk must fail the step'
    } catch (RuntimeException e) {
        assert e.message.contains('97 MB free'): e.message
        assert e.message.contains('1500 MB required'): e.message
        assert e.message.contains('Aborting before running Terraform'): e.message
    }
    assert h.sh.size() == 1: 'only df may run, nothing else'
    assert !h.sh[0].contains('docker run'): 'no container may start'
    assert h.sh[0].startsWith('df -Pk')
    assert h.withEnv.isEmpty(): 'no environment must be configured'
}

test('validates every configured root') {
    def h = newStep('terraformValidate')
    h.script.call(roots: ['infra/terraform/envs/dev', 'infra/terraform/envs/stage',
                          'infra/terraform/envs/prod', 'infra/terraform/backend-bootstrap'],
                  fmtPath: 'infra/terraform')
    // df + mkdir + fmt + (init + validate) * 4
    assert h.sh.size() == 11
    assert h.sh.count { it.contains(' fmt -check ') } == 1
    assert h.sh.count { it.contains(' init -backend=false ') } == 4
    assert h.sh.count { it.contains(' validate ') } == 4
    assert h.withEnv.size() == 4: 'every init must receive the plugin cache'
}

test('rejects an empty root list and a missing root') {
    def empty = newStep('terraformValidate')
    try {
        empty.script.call(roots: [], fmtPath: 'infra/terraform')
        assert false: 'empty roots must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('roots are required')
    }

    def missing = newStep('terraformValidate', [missing: ['infra/terraform/ghost']])
    try {
        missing.script.call(roots: ['infra/terraform/ghost'], fmtPath: 'infra/terraform')
        assert false: 'missing root must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('does not exist')
    }
    assert missing.sh.isEmpty(): 'nothing must run when a root does not exist'
}

println 'trivyScan'
test('scans with severity HIGH,CRITICAL and a blocking exit code') {
    def h = newStep('trivyScan', [files: ['trivy-iac-report-42.txt': 'report body'],
                                  missing: ['.trivyignore.yaml']])
    h.script.call(paths: ['infra/terraform'])

    assert h.sh.size() == 1
    String cmd = h.sh[0]
    assert cmd.contains('config infra/terraform')
    assert cmd.contains('--severity HIGH,CRITICAL')
    assert cmd.contains('--exit-code 1')
    assert cmd.contains('--format table --output trivy-iac-report-42.txt --quiet')
    // H2: the cache lives in the workspace of the job, never in a shared path
    assert cmd.contains('--cache-dir /ws/.trivy-cache')
    assert cmd.contains('--skip-dirs .trivy-cache')
    assert cmd.contains('--skip-dirs "**/.trivy-cache"')
    assert cmd.contains('--skip-dirs .terraform')
    assert cmd.contains("'*.tfstate*'"): 'the state must be excluded'
    assert cmd.contains("'**/*.tfstate*'"): 'the state must be excluded (nested)'
    assert cmd.contains("'*.tfplan*'"): 'saved plans must be excluded'
    assert cmd.contains("'**/*.tfplan*'"): 'saved plans must be excluded (nested)'
    assert !cmd.contains('--ignorefile'): 'no ignore file exists yet'
    assert !cmd.contains('-e AWS_'): 'the scan must not receive credentials'
    assert !cmd.contains('secret'): 'trivy config must not scan for secrets'
    assert !cmd.contains('/jh/.trivy-cache'): 'the shared cache must not be used'

    assert h.archived.contains('trivy-iac-report-42.txt'): 'the report must be archived'
    assert h.logs.any { it.contains('report body') }: 'the report must be echoed'
}

test('passes the ignore file when it exists') {
    def h = newStep('trivyScan', [files: ['trivy-iac-report-42.txt': 'clean']])
    h.script.call(paths: ['infra/terraform'])
    assert h.sh[0].contains('--ignorefile .trivyignore.yaml')
}

test('blocks the build on HIGH/CRITICAL findings and keeps the evidence') {
    def h = newStep('trivyScan', [status: 1, files: ['trivy-iac-report-42.txt': 'CRITICAL findings']])
    try {
        h.script.call(paths: ['infra/terraform'])
        assert false: 'findings must fail the step'
    } catch (RuntimeException e) {
        assert e.message.contains('HIGH/CRITICAL')
        assert e.message.contains('.trivyignore.yaml'): 'the message must point to the documented exception'
        assert e.message.contains('Report(s) archived: trivy-iac-report-42.txt'): e.message
    }
    assert h.archived.contains('trivy-iac-report-42.txt'): 'the report must survive the failure'
}

test('never archives the report of a previous build as evidence') {
    // build 42 fails before Trivy writes anything; only build 41 report exists
    def h = newStep('trivyScan', [status: 1,
                                  files: ['trivy-iac-report-41.txt': 'OLD EVIDENCE'],
                                  missing: ['trivy-iac-report-42.txt']])
    try {
        h.script.call(paths: ['infra/terraform'])
        assert false: 'the step must fail'
    } catch (RuntimeException e) {
        assert !e.message.contains('Report(s) archived'): e.message
    }
    assert h.archived.isEmpty(): 'the report of build 41 must not be archived for build 42'
    assert h.logs.every { !it.contains('OLD EVIDENCE') }: 'the old report must not be echoed'
}

test('reports correctly when no report was generated') {
    def h = newStep('trivyScan', [status: 1, missing: ['trivy-iac-report-42.txt']])
    try {
        h.script.call(paths: ['infra/terraform'])
        assert false: 'the step must fail'
    } catch (RuntimeException e) {
        assert e.message.contains('No report was generated'): e.message
        assert !e.message.contains('Report(s) archived'): e.message
        assert e.message.contains('.trivyignore.yaml'): e.message
    }
    assert h.archived.isEmpty()
}

test('scans one path per invocation and names one report per path') {
    def h = newStep('trivyScan')
    h.script.call(paths: ['infra/terraform/envs/dev', 'infra/terraform/envs/prod'])
    assert h.sh.size() == 2: 'trivy config accepts a single target'
    assert h.sh[0].contains('config infra/terraform/envs/dev')
    assert h.sh[1].contains('config infra/terraform/envs/prod')
    assert h.sh[0].contains('--output trivy-iac-report-42-infra-terraform-envs-dev.txt')
    assert h.sh[1].contains('--output trivy-iac-report-42-infra-terraform-envs-prod.txt')
    assert h.archived.size() == 2
}

test('rejects an empty path list and a missing path') {
    def empty = newStep('trivyScan')
    try {
        empty.script.call(paths: [])
        assert false: 'empty paths must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('paths are required')
    }

    def missing = newStep('trivyScan', [missing: ['infra/terraform/ghost']])
    try {
        missing.script.call(paths: ['infra/terraform/ghost'])
        assert false: 'missing path must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('does not exist')
    }
    assert missing.sh.isEmpty(): 'nothing must run when the path does not exist'
}

println 'terraformPlan'
test('plans DEV against the real S3 backend with the credential bound by name') {
    def h = newStep('terraformPlan')
    def result = h.script.call(root: 'infra/terraform/envs/dev')

    // df + mkdir (plugin cache) + rm (stale plan) + docker init + docker plan
    assert h.sh.size() == 5: "expected 5 commands, got ${h.sh.size()}"
    assert h.sh[0].startsWith('df -Pk'): 'the disk must be checked first'
    assert !h.sh[0].contains('docker run'): 'no container may start before the disk check'
    assert h.sh[1].contains('.terraform-plugin-cache'): 'the plugin cache must be created'
    assert h.sh[1].contains('/var/jenkins_home/workspace/circleguard_dev/')
    assert h.sh[2] == 'rm -f "infra/terraform/envs/dev/ci-dev.tfplan"': h.sh[2]

    String init = h.sh[3]
    String plan = h.sh[4]
    assert init.contains(' init -backend=true -no-color -input=false'): init
    assert !init.contains('-backend=false'): 'the REAL S3 backend is required'
    assert !init.contains('-reconfigure') && !init.contains('-migrate-state'): 'the state must never be reconfigured'
    assert init.contains("-w '/ws/infra/terraform/envs/dev'")
    assert plan.contains(' plan -no-color -input=false -lock=true -detailed-exitcode ' +
                         '-out=ci-dev.tfplan'): plan
    assert plan.contains("-w '/ws/infra/terraform/envs/dev'")

    // env vars by NAME only: no value, no interpolation, no secret in a command
    [init, plan].each { String cmd ->
        ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_DEFAULT_REGION',
         'TF_IN_AUTOMATION', 'TF_INPUT', 'TF_PLUGIN_CACHE_DIR'].each { String v ->
            assert cmd.contains("-e ${v}"): "missing -e ${v} in ${cmd}"
            assert !cmd.contains("-e ${v}="): "the VALUE of ${v} must not be in the command: ${cmd}"
        }
        assert !cmd.contains('${'): "no shell interpolation of a value: ${cmd}"
        assert !cmd.contains(' apply'): "apply must never run: ${cmd}"
        assert !cmd.contains('destroy'): "destroy must never run: ${cmd}"
        assert !cmd.contains('-replace'): "no forced replacement: ${cmd}"
        assert !cmd.contains('-upgrade'): "the lockfile must not be upgraded: ${cmd}"
        assert !cmd.contains('-var '): "variables are never injected: ${cmd}"
    }

    // the credential is bound exactly once, with the required id and variables
    assert h.withCredentials.size() == 1: 'the credential must be bound once'
    assert h.withCredentials[0].size() == 1
    Map cred = h.withCredentials[0][0]
    assert cred.credentialsId == 'aws-terraform-credentials': cred
    assert cred.usernameVariable == 'AWS_ACCESS_KEY_ID': cred
    assert cred.passwordVariable == 'AWS_SECRET_ACCESS_KEY': cred

    // non-secret environment, scoped with withEnv
    assert h.withEnv.size() == 1: 'the environment must be scoped to the Terraform commands'
    List envEntries = h.withEnv[0]
    assert envEntries.contains('AWS_DEFAULT_REGION=us-east-1'): envEntries
    assert envEntries.contains('TF_IN_AUTOMATION=1'): envEntries
    assert envEntries.contains('TF_INPUT=0'): envEntries
    assert envEntries.contains('TF_PLUGIN_CACHE_DIR=/ws/.terraform-plugin-cache'): envEntries

    // the plan stays in the workspace and is never downloadable
    assert h.archived.isEmpty(): 'the plan must not be archived as an artifact'
    assert result.root == 'infra/terraform/envs/dev'
    assert result.planFile == 'infra/terraform/envs/dev/ci-dev.tfplan'
    assert result.status == 0
    assert result.changes == false
    assert h.logs.any { it.contains('NO changes') }: h.logs
}

test('reports changes when -detailed-exitcode returns 2') {
    def h = newStep('terraformPlan', [status: 2])
    def result = h.script.call(root: 'infra/terraform/envs/dev')
    assert result.status == 2
    assert result.changes == true
    assert h.logs.any { it.contains('CHANGES pending') }: h.logs
    assert h.archived.isEmpty()
}

test('fails safely on exit code 1 and never widens the IAM policies') {
    def h = newStep('terraformPlan', [status: 1])
    try {
        h.script.call(root: 'infra/terraform/envs/dev')
        assert false: 'a failing plan must fail the step'
    } catch (RuntimeException e) {
        assert e.message.contains('exit 1'): e.message
        assert e.message.contains('AccessDenied'): e.message
        assert e.message.contains('do NOT widen'): e.message
    }
    assert h.archived.isEmpty(): 'no evidence of a failed plan may be archived'
}

test('fails when Terraform did not write the plan file') {
    def h = newStep('terraformPlan', [missing: ['infra/terraform/envs/dev/ci-dev.tfplan']])
    try {
        h.script.call(root: 'infra/terraform/envs/dev')
        assert false: 'a missing plan file must fail the step'
    } catch (RuntimeException e) {
        assert e.message.contains('did not write the plan file'): e.message
        assert e.message.contains('ci-dev.tfplan'): e.message
    }
}

test('aborts before Terraform and before binding the credential when the disk is full') {
    def h = newStep('terraformPlan', [dfOutput: LOW_DF])
    try {
        h.script.call(root: 'infra/terraform/envs/dev')
        assert false: 'an insufficient disk must fail the step'
    } catch (RuntimeException e) {
        assert e.message.contains('97 MB free'): e.message
        assert e.message.contains('1500 MB required'): e.message
        assert e.message.contains('Aborting before running Terraform'): e.message
    }
    assert h.sh.size() == 1: 'only df may run, nothing else'
    assert h.sh[0].startsWith('df -Pk')
    assert !h.sh[0].contains('docker run')
    assert h.withCredentials.isEmpty(): 'the credential must not be bound on the abort path'
    assert h.withEnv.isEmpty()
    assert h.archived.isEmpty()
}

test('fails safely when the root or its versions.tf is missing') {
    def noRoot = newStep('terraformPlan', [missing: ['infra/terraform/envs/dev']])
    try {
        noRoot.script.call(root: 'infra/terraform/envs/dev')
        assert false: 'a missing root must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('does not exist'): e.message
    }
    assert noRoot.sh.isEmpty(): 'nothing must run when the root does not exist'
    assert noRoot.withCredentials.isEmpty()

    def noVersions = newStep('terraformPlan', [missing: ['infra/terraform/envs/dev/versions.tf']])
    try {
        noVersions.script.call(root: 'infra/terraform/envs/dev')
        assert false: 'a root without versions.tf must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('versions.tf'): e.message
    }
    assert noVersions.sh.isEmpty(): 'nothing must run without the backend declaration'
    assert noVersions.withCredentials.isEmpty()
}

test('rejects an unsafe root, a plan name without .tfplan and an empty credential id') {
    def noRoot = newStep('terraformPlan')
    try {
        noRoot.script.call(root: null)
        assert false: 'a missing root must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('root is required'): e.message
    }

    def escaping = newStep('terraformPlan')
    try {
        escaping.script.call(root: '../../secrets')
        assert false: 'a root escaping the workspace must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('relative path'): e.message
    }

    def absolute = newStep('terraformPlan')
    try {
        absolute.script.call(root: '/etc')
        assert false: 'an absolute root must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('relative path'): e.message
    }

    def badName = newStep('terraformPlan')
    try {
        badName.script.call(root: 'infra/terraform/envs/dev', planFile: 'plan.txt')
        assert false: 'a plan file without .tfplan must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('.tfplan'): e.message
    }

    def noCredential = newStep('terraformPlan')
    try {
        noCredential.script.call(root: 'infra/terraform/envs/dev', credentialsId: '')
        assert false: 'an empty credential id must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('credentialsId is required'): e.message
    }
    assert noCredential.sh.isEmpty(): 'nothing must run without a credential id'
}

test('never runs apply and never archives the plan (source level)') {
    assert !new File(root, 'vars/terraformApply.groovy').exists():
        'apply is not part of this phase'
    String step = new File(root, 'vars/terraformPlan.groovy').text
    assert !step.contains('archiveArtifacts'): 'the plan must not be downloadable'
    assert step.contains("command: 'init -backend=true -no-color -input=false'"):
        'the plan must initialise the real backend'
    assert step.contains('withCredentials'): 'the credential must be bound explicitly'
    assert step.contains("usernameVariable: 'AWS_ACCESS_KEY_ID'")
    assert step.contains("passwordVariable: 'AWS_SECRET_ACCESS_KEY'")
    assert step.contains('-detailed-exitcode')
    assert step.contains('terraformValidate.freeSpaceMB'): 'the free-space parser must be reused'
}

println 'PipelineConfig'
test('keeps the new stages disabled by default with pinned images and DEV only') {
    def cls = loader.parseClass(new File(root, 'src/org/circleguard/ci/PipelineConfig.groovy'))
    def cfg = cls.getConstructor(Map).newInstance([:])

    assert cfg.terraformValidate == false: 'the stage must be off by default'
    assert cfg.trivyScan == false: 'the stage must be off by default'

    assert cfg.terraformImage.contains(':') && !cfg.terraformImage.endsWith(':latest')
    assert cfg.trivyImage.contains(':') && !cfg.trivyImage.endsWith(':latest')

    // only DEV until the first real run is validated
    assert cfg.terraformRoots == ['infra/terraform/envs/dev']: cfg.terraformRoots
    assert cfg.terraformFmtPath == 'infra/terraform'
    assert cfg.terraformMinFreeSpaceMB == 1500
    assert cfg.trivyPaths == ['infra/terraform']
    assert cfg.trivySeverity == 'HIGH,CRITICAL'
    assert cfg.terraformValidateTimeout > 0 && cfg.trivyTimeout > 0
}

test('accepts the parameters from the Jenkinsfile') {
    def cls = loader.parseClass(new File(root, 'src/org/circleguard/ci/PipelineConfig.groovy'))
    def cfg = cls.getConstructor(Map).newInstance(
        [terraformValidate: true, trivyScan: true,
         terraformRoots: ['infra/terraform/envs/stage'],
         terraformMinFreeSpaceMB: 3000,
         trivySeverity: 'CRITICAL', trivyImage: 'aquasec/trivy:0.76.2'])

    assert cfg.terraformValidate == true
    assert cfg.trivyScan == true
    assert cfg.terraformRoots == ['infra/terraform/envs/stage']
    assert cfg.terraformMinFreeSpaceMB == 3000
    assert cfg.trivySeverity == 'CRITICAL'
    assert cfg.trivyImage == 'aquasec/trivy:0.76.2'
    // untouched defaults keep their value
    assert cfg.terraformFmtPath == 'infra/terraform'
    assert cfg.publish == false
}

test('keeps Terraform plan disabled by default, DEV only and without a credential') {
    def cls = loader.parseClass(new File(root, 'src/org/circleguard/ci/PipelineConfig.groovy'))
    def cfg = cls.getConstructor(Map).newInstance([:])

    assert cfg.terraformPlan == false: 'the plan stage must be off by default'
    assert cfg.terraformPlanRoot == 'infra/terraform/envs/dev': cfg.terraformPlanRoot
    assert cfg.terraformPlanBranches == ['dev']: cfg.terraformPlanBranches
    assert cfg.terraformAwsCredentialsId == 'aws-terraform-credentials'
    assert cfg.terraformAwsRegion == 'us-east-1'
    assert cfg.terraformPlanTimeout > 0
}

test('accepts the Terraform plan parameters from the Jenkinsfile') {
    def cls = loader.parseClass(new File(root, 'src/org/circleguard/ci/PipelineConfig.groovy'))
    def cfg = cls.getConstructor(Map).newInstance(
        [terraformPlan: true,
         terraformPlanRoot: 'infra/terraform/envs/stage',
         terraformPlanBranches: ['main'],
         terraformAwsCredentialsId: 'other-credentials',
         terraformAwsRegion: 'eu-west-1',
         terraformPlanTimeout: 45])

    assert cfg.terraformPlan == true
    assert cfg.terraformPlanRoot == 'infra/terraform/envs/stage'
    assert cfg.terraformPlanBranches == ['main']
    assert cfg.terraformAwsCredentialsId == 'other-credentials'
    assert cfg.terraformAwsRegion == 'eu-west-1'
    assert cfg.terraformPlanTimeout == 45
    // untouched defaults keep their value
    assert cfg.terraformValidate == false
    assert cfg.trivyScan == false
    assert cfg.publish == false
}

println 'circleguardPipeline (integration, source level)'
test('still compiles with the new stages') {
    // a child loader so that PipelineConfig is visible to the import of the entry point
    def child = new GroovyClassLoader(loader)
    child.parseClass(new File(root, 'src/org/circleguard/ci/PipelineConfig.groovy'))
    child.parseClass(new File(root, 'vars/circleguardPipeline.groovy'))
    child.parseClass(new File(root, 'vars/terraformValidate.groovy'))
    child.parseClass(new File(root, 'vars/terraformPlan.groovy'))
    child.parseClass(new File(root, 'vars/trivyScan.groovy'))
    child.parseClass(new File(root, 'vars/runInContainer.groovy'))
}

test('declares the new stages before Publish images and gates them by config') {
    String text = new File(root, 'vars/circleguardPipeline.groovy').text

    assert text.contains("stage('Terraform validate')")
    assert text.contains("stage('Trivy IaC')")
    assert text.indexOf("stage('Terraform validate')") < text.indexOf("stage('Publish images')")
    assert text.indexOf("stage('Trivy IaC')") < text.indexOf("stage('Publish images')")

    // both stages are opt-in: the default behaviour of the pipeline does not change
    String terraformStage = text.substring(text.indexOf("stage('Terraform validate')"),
                                           text.indexOf("stage('Publish images')"))
    assert terraformStage.contains('expression { cfg.terraformValidate }')
    assert terraformStage.contains('minFreeSpaceMB: cfg.terraformMinFreeSpaceMB')
    String trivyStage = text.substring(text.indexOf("stage('Trivy IaC')"),
                                       text.indexOf("stage('Publish images')"))
    assert trivyStage.contains('expression { cfg.trivyScan }')
    assert trivyStage.contains('severity: cfg.trivySeverity')
}

test('declares the Terraform plan stage between Trivy and Publish, gated to dev') {
    String text = new File(root, 'vars/circleguardPipeline.groovy').text

    assert text.contains("stage('Terraform plan')")
    int plan = text.indexOf("stage('Terraform plan')")
    assert plan > text.indexOf("stage('Trivy IaC')"): 'the plan must run after the IaC scan'
    assert plan < text.indexOf("stage('Publish images')"): 'the plan must run before the images are built'

    String block = text.substring(plan, text.indexOf("stage('Publish images')"))
    // flag AND branch: PRs and every other branch are excluded from the credential
    assert block.contains('cfg.terraformPlan && cfg.terraformPlanBranches.contains(env.BRANCH_NAME)')
    assert block.contains('timeout(time: cfg.terraformPlanTimeout')
    assert block.contains('root: cfg.terraformPlanRoot')
    assert block.contains('credentialsId: cfg.terraformAwsCredentialsId')
    assert block.contains('region: cfg.terraformAwsRegion')
    assert block.contains('minFreeSpaceMB: cfg.terraformMinFreeSpaceMB')
    assert !block.contains('terraformApply'): 'apply is not part of this phase'
}

test('does not introduce any apply stage or step') {
    String text = new File(root, 'vars/circleguardPipeline.groovy').text
    assert !text.contains("stage('Terraform apply')"): 'no apply stage in this phase'
    assert !text.contains('terraformApply('): 'no apply step in this phase'
    assert !new File(root, 'vars/terraformApply.groovy').exists():
        'vars/terraformApply.groovy must not exist yet'
}

test('keeps every pre-existing stage') {
    String text = new File(root, 'vars/circleguardPipeline.groovy').text
    ['Checkout', 'Build', 'Tests', 'Integration tests', 'SonarQube', 'Publish images',
     'Deploy', 'Verify deployment', 'Smoke tests', 'E2E tests',
     'Promote to stage', 'Promote to prod'].each { String stage ->
        assert text.contains("stage('${stage}')"): "stage ${stage} disappeared"
    }
    assert text.contains('disableConcurrentBuilds(abortPrevious: true)')
}

test('does not touch runE2E (out of scope of this phase)') {
    String e2e = new File(root, 'vars/runE2E.groovy').text
    assert e2e.contains('-v ${volume}:/jh'): 'runE2E must keep mounting the whole volume'
}

println ''
println "passed: ${passed}, failed: ${failures.size()}"
failures.each { println "  - ${it}" }
System.exit(failures.isEmpty() ? 0 : 1)
