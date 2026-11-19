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
 * Returns a map with: script, sh (recorded commands), logs, archived, written
 * (file -> content written by the stubbed writeFile), withEnv,
 * withCredentials (the bindings recorded by the stubbed withCredentials),
 * junit (the testResults published by the stubbed junit) and trace (the ordered
 * record of sh commands plus the stubbed sibling steps: ensureBuildx,
 * dockerCleanup, trivyImageScan).
 * opts.status               exit code returned by sh(..., returnStatus: true)
 * opts.missing              paths for which fileExists() answers false
 * opts.files                contents returned by readFile()
 * opts.dfOutput             stdout of the `df` call (free-space check)
 * opts.failSh               when true, every sh throws (checks the `finally` evidence)
 * opts.failShMessage        message used by failSh / failShContains (e.g. AccessDenied)
 * opts.failShContains       every sh whose text contains this value throws
 * opts.failArchiveContains  archiveArtifacts throws for the files containing this value
 * opts.failWriteFileContains writeFile throws for the files whose name contains this value
 * opts.failScan             when true, the trivyImageScan stub throws (checks the push gate)
 */
def newStep = { String name, Map opts = [:] ->
    def script = loader.parseClass(new File(root, "vars/${name}.groovy")).newInstance()
    Map b = [
        env     : (opts.containsKey('env') ? opts.env :
                   [WORKSPACE: '/var/jenkins_home/workspace/circleguard_dev',
                    BUILD_NUMBER: '42', GIT_COMMIT: 'abc1234']),
        sh      : [],
        logs    : [],
        archived: [],
        written : [:],
        withEnv : [],
        withCredentials: [],
        junit   : [],
        trace   : []     // ordered: sh commands + stubbed sibling steps (order assertions)
    ]
    def binding = new Binding()
    binding.setVariable('env', b.env)
    binding.setVariable('echo', { Object m -> b.logs << m.toString() })
    binding.setVariable('error', { Object m -> throw new RuntimeException(m.toString()) })
    binding.setVariable('sh', { Object arg ->
        String scriptText = (arg instanceof Map) ? arg.script.toString() : arg.toString()
        b.sh << scriptText
        b.trace << scriptText
        // opts.failSh makes every command fail: used to check the `finally`
        // blocks that must publish their evidence even when the step blows up.
        // opts.failShMessage changes the message of that failure (e.g. to simulate
        // an AccessDenied coming from AWS).
        if (opts.failSh) {
            throw new RuntimeException(opts.failShMessage ?: 'simulated command failure')
        }
        // opts.failShContains fails only the commands containing that text, so a
        // test can target one step (e.g. the cleanup of terraformApply).
        if (opts.failShContains && scriptText.contains(opts.failShContains)) {
            throw new RuntimeException(opts.failShMessage ?: 'simulated command failure')
        }
        if (arg instanceof Map) {
            if (arg.returnStatus) {
                return (opts.status ?: 0) as int
            }
            if (arg.returnStdout) {
                if (scriptText.startsWith('df ')) {
                    return (opts.dfOutput ?: ENOUGH_DF)
                }
                return (opts.stdout ?: '')
            }
        }
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
    // writeFile records what the step wrote (sidecars, evidence, markers) and can
    // be made to fail for one file (opts.failWriteFileContains).
    binding.setVariable('writeFile', { Object a ->
        String file = (a instanceof Map && a.file != null) ? a.file.toString() : ''
        if (opts.failWriteFileContains && file.contains(opts.failWriteFileContains)) {
            throw new RuntimeException('simulated writeFile failure')
        }
        if (file) {
            b.written[file] = (a instanceof Map && a.text != null) ? a.text.toString() : ''
        }
    })
    binding.setVariable('archiveArtifacts', { Object a ->
        String artifacts = (a instanceof Map) ? a.artifacts.toString() : a.toString()
        // opts.failArchiveContains fails the archiving of one file, so the tests
        // can tell "evidence not written" from "written but not archived".
        if (opts.failArchiveContains && artifacts.contains(opts.failArchiveContains)) {
            throw new RuntimeException('simulated archiveArtifacts failure')
        }
        b.archived << artifacts
    })
    binding.setVariable('junit', { Object a ->
        b.junit << (a instanceof Map ? a.testResults : a.toString())
    })
    binding.setVariable('timeout', { Object o, Closure c -> c.call() })
    script.binding = binding

    // Steps call other steps through the same binding (runInContainer).
    def container = loader.parseClass(new File(root, 'vars/runInContainer.groovy')).newInstance()
    container.binding = binding
    binding.setVariable('runInContainer', { Map p -> container.call(p) })

    // Steps called by publishImages are stubbed and recorded in `trace`, so the
    // order build -> scan -> push -> rm can be asserted without running Docker.
    // opts.failScan makes the image scan fail (checks that the push is skipped
    // and that the `finally` still logs out of the registry).
    binding.setVariable('ensureBuildx', { b.trace << 'ensureBuildx()' })
    binding.setVariable('dockerCleanup', { b.trace << 'dockerCleanup()' })
    binding.setVariable('trivyImageScan', { Map p ->
        b.trace << (opts.failScan ? "trivyImageScan(${p.ref}) FAILED" : "trivyImageScan(${p.ref})")
        if (opts.failScan) {
            throw new RuntimeException('simulated image scan failure')
        }
    })

    [script: script, sh: b.sh, logs: b.logs, archived: b.archived, written: b.written,
     withEnv: b.withEnv, withCredentials: b.withCredentials, junit: b.junit,
     trace: b.trace]
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
// SHA-256 the step computes for ci-dev-b42.tfplan (64 hex chars) when sha256sum works
String PLAN_SHA = 'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210'

test('plans DEV against the real S3 backend with the credential bound by name') {
    def h = newStep('terraformPlan', [stdout: PLAN_SHA])
    def result = h.script.call(root: 'infra/terraform/envs/dev')

    // df + mkdir (plugin cache) + rm (stale plan) + docker init + docker plan + sha256sum
    assert h.sh.size() == 6: "expected 6 commands, got ${h.sh.size()}"
    assert h.sh[0].startsWith('df -Pk'): 'the disk must be checked first'
    assert !h.sh[0].contains('docker run'): 'no container may start before the disk check'
    assert h.sh[1].contains('.terraform-plugin-cache'): 'the plugin cache must be created'
    assert h.sh[1].contains('/var/jenkins_home/workspace/circleguard_dev/')
    assert h.sh[2] == 'rm -f "infra/terraform/envs/dev/ci-dev-b42.tfplan" ' +
                      '"infra/terraform/envs/dev/ci-dev-b42.tfplan.info"': h.sh[2]
    assert h.sh[5] == 'sha256sum "infra/terraform/envs/dev/ci-dev-b42.tfplan"': h.sh[5]

    String init = h.sh[3]
    String plan = h.sh[4]
    assert init.contains(' init -backend=true -no-color -input=false'): init
    assert !init.contains('-backend=false'): 'the REAL S3 backend is required'
    assert !init.contains('-reconfigure') && !init.contains('-migrate-state'): 'the state must never be reconfigured'
    assert init.contains("-w '/ws/infra/terraform/envs/dev'")
    assert plan.contains(' plan -no-color -input=false -lock=true -detailed-exitcode ' +
                         '-out=ci-dev-b42.tfplan'): plan
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
    assert result.planFile == 'infra/terraform/envs/dev/ci-dev-b42.tfplan'
    assert result.planInfo == 'infra/terraform/envs/dev/ci-dev-b42.tfplan.info'
    assert result.status == 0
    assert result.changes == false
    assert h.logs.any { it.contains('NO changes') }: h.logs

    // sidecar with the provenance of THIS plan: the build number is part of the
    // name AND of the sidecar, so terraformApply can reject a plan of another
    // build or another revision before running anything
    String info = h.written['infra/terraform/envs/dev/ci-dev-b42.tfplan.info']
    assert info != null: "sidecar not written: ${h.written}"
    assert info.contains('build=42'): info
    assert info.contains('commit=abc1234'): info
    assert info.contains('root=infra/terraform/envs/dev'): info
    assert info.contains('changes=false'): info
    assert info.contains('status=0'): info
    assert info.contains("sha256=${PLAN_SHA}"): info
    assert info.contains('createdAt='): info
}

test('fails closed when sha256sum is not available') {
    def h = newStep('terraformPlan', [failShContains: 'sha256sum'])
    try {
        h.script.call(root: 'infra/terraform/envs/dev')
        assert false: 'without sha256sum the plan must not leave a sidecar'
    } catch (RuntimeException e) {
        assert e.message.contains('sha256sum is required'): e.message
        assert e.message.contains('aborting before the sidecar is written'): e.message
    }
    assert h.written.isEmpty(): 'no sidecar without a hash'
    assert h.sh.count { it.contains('docker run') } == 2: 'the plan itself did run'
    assert h.sh.any { it.startsWith('sha256sum') }: 'the hash was attempted'
}

test('reports changes when -detailed-exitcode returns 2') {
    def h = newStep('terraformPlan', [status: 2, stdout: PLAN_SHA])
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
    def h = newStep('terraformPlan',
                    [missing: ['infra/terraform/envs/dev/ci-dev-b42.tfplan']])
    try {
        h.script.call(root: 'infra/terraform/envs/dev')
        assert false: 'a missing plan file must fail the step'
    } catch (RuntimeException e) {
        assert e.message.contains('did not write the plan file'): e.message
        assert e.message.contains('ci-dev-b42.tfplan'): e.message
    }
    assert h.written.isEmpty(): 'no sidecar may be written without a plan'
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
    String step = new File(root, 'vars/terraformPlan.groovy').text
    assert !step.contains('apply -no-color'): 'the plan step must never apply'
    assert !step.contains('archiveArtifacts'): 'the plan must not be downloadable'
    assert step.contains("command: 'init -backend=true -no-color -input=false'"):
        'the plan must initialise the real backend'
    assert step.contains('withCredentials'): 'the credential must be bound explicitly'
    assert step.contains("usernameVariable: 'AWS_ACCESS_KEY_ID'")
    assert step.contains("passwordVariable: 'AWS_SECRET_ACCESS_KEY'")
    assert step.contains('-detailed-exitcode')
    assert step.contains('terraformValidate.freeSpaceMB'): 'the free-space parser must be reused'
}

println 'terraformApply'
String APPLY_ROOT = 'infra/terraform/envs/dev'
String APPLY_PLAN = 'ci-dev-b42.tfplan'
String APPLY_PLAN_PATH = "${APPLY_ROOT}/${APPLY_PLAN}"
String APPLY_INFO_PATH = "${APPLY_PLAN_PATH}.info"
String APPLY_MARKER = "${APPLY_PLAN_PATH}.applied"
String APPLY_EVIDENCE = "${APPLY_ROOT}/terraform-apply-dev-b42.txt"
// SHA-256 the plan stage would have written for ci-dev-b42.tfplan (64 hex chars)
String APPLY_SHA = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
String APPLY_SIDECAR = 'build=42\ncommit=abc1234\nroot=infra/terraform/envs/dev\n' +
                       "changes=true\nstatus=2\nsha256=${APPLY_SHA}\n" +
                       'createdAt=2026-11-18T18:00:00Z\n'

// env of a build whose plan stage produced the plan above for `changes`.
def applyEnv = { String changes, Map extra = [:] ->
    Map e = [WORKSPACE: '/var/jenkins_home/workspace/circleguard_dev',
             BUILD_NUMBER: '42', GIT_COMMIT: 'abc1234', BRANCH_NAME: 'dev',
             TF_PLAN_BUILD: '42', TF_PLAN_ROOT: APPLY_ROOT,
             TF_PLAN_FILE: APPLY_PLAN_PATH, TF_PLAN_INFO: APPLY_INFO_PATH,
             TF_PLAN_CHANGES: changes]
    e.putAll(extra)
    e
}

test('applies the plan of this build with -lock=true and records the evidence') {
    def h = newStep('terraformApply', [env: applyEnv('true'),
                                       files: [(APPLY_INFO_PATH): APPLY_SIDECAR],
                                       missing: [APPLY_MARKER],
                                       stdout: APPLY_SHA])
    def result = h.script.call(root: APPLY_ROOT)

    // df + sha256sum + mkdir + docker init + docker apply + cleanup
    assert h.sh.size() == 6: "expected 6 commands, got ${h.sh.size()}"
    assert h.sh[0].startsWith('df -Pk'): 'the disk must be checked first'
    assert !h.sh[0].contains('docker run'): 'no container before the disk check'
    assert h.sh[1] == "sha256sum \"${APPLY_PLAN_PATH}\"": h.sh[1]
    assert h.sh[2].contains('.terraform-plugin-cache'): h.sh[2]

    String init = h.sh[3]
    String apply = h.sh[4]
    assert init.contains(' init -backend=true -no-color -input=false'): init
    assert !init.contains('-backend=false'): 'the real backend is required'
    assert !init.contains('-reconfigure') && !init.contains('-migrate-state')
    assert apply.contains(" apply -no-color -input=false -lock=true ${APPLY_PLAN}"): apply
    assert apply.contains("-w '/ws/${APPLY_ROOT}'")
    assert !apply.contains('-lock=false'): 'the lock must never be disabled'
    assert !apply.contains('-auto-approve'): 'a saved plan never needs -auto-approve'
    assert !apply.contains('-destroy'): 'never destroy'
    assert !apply.contains('-replace'): 'never force a replacement'
    assert !apply.contains(' output'): 'no Terraform output is echoed'

    [init, apply].each { String cmd ->
        ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_DEFAULT_REGION',
         'TF_IN_AUTOMATION', 'TF_INPUT', 'TF_PLUGIN_CACHE_DIR'].each { String v ->
            assert cmd.contains("-e ${v}"): "missing -e ${v} in ${cmd}"
            assert !cmd.contains("-e ${v}="): "the VALUE of ${v} must not be in the command: ${cmd}"
        }
        assert !cmd.contains('${'): "no interpolation of a value: ${cmd}"
    }

    // the shared credential, bound exactly once and only around init/apply
    assert h.withCredentials.size() == 1
    Map cred = h.withCredentials[0][0]
    assert cred.credentialsId == 'aws-terraform-credentials': cred
    assert cred.usernameVariable == 'AWS_ACCESS_KEY_ID': cred
    assert cred.passwordVariable == 'AWS_SECRET_ACCESS_KEY': cred
    assert h.withEnv[0].contains('AWS_DEFAULT_REGION=us-east-1'): h.withEnv

    // order on success: marker -> evidence -> cleanup
    assert h.written.containsKey(APPLY_MARKER): "marker missing: ${h.written}"
    assert h.written[APPLY_MARKER].contains('applied build=42'): h.written[APPLY_MARKER]
    assert h.written[APPLY_MARKER].contains('commit=abc1234'): h.written[APPLY_MARKER]
    assert h.written[APPLY_EVIDENCE]?.contains('Outcome     : APPLIED'): h.written
    assert h.written[APPLY_EVIDENCE]?.contains('Build       : 42'): h.written
    assert h.archived == [APPLY_EVIDENCE]: h.archived
    assert h.sh[5] == "rm -f \"${APPLY_PLAN_PATH}\" \"${APPLY_INFO_PATH}\"": h.sh[5]
    assert h.logs.any { it.contains('plan hash verified') }: h.logs

    assert result.root == APPLY_ROOT
    assert result.planFile == APPLY_PLAN_PATH
    assert result.status == 'APPLIED'
    // no credential, no output and no state value in the evidence
    String evidenceText = h.written[APPLY_EVIDENCE]
    assert !evidenceText.contains('AWS_SECRET'): evidenceText
    assert !evidenceText.contains('SecretAccessKey'): evidenceText
}

test('registers SKIPPED_NO_CHANGES and omits init and apply when the plan is clean') {
    String sidecar = APPLY_SIDECAR.replace('changes=true', 'changes=false')
                                   .replace('status=2', 'status=0')
    def h = newStep('terraformApply', [env: applyEnv('false'),
                                       files: [(APPLY_INFO_PATH): sidecar],
                                       missing: [APPLY_MARKER]])
    def result = h.script.call(root: APPLY_ROOT)

    assert h.sh.isEmpty(): "nothing must run without changes: ${h.sh}"
    assert h.withCredentials.isEmpty(): 'no credential without changes'
    assert h.withEnv.isEmpty(): 'no environment without changes'
    assert result.status == 'SKIPPED_NO_CHANGES': result
    assert h.written[APPLY_EVIDENCE]?.contains('SKIPPED_NO_CHANGES'): h.written
    assert h.archived == [APPLY_EVIDENCE]: h.archived
    assert !h.written.containsKey(APPLY_MARKER): 'no marker without an apply'
}

test('fails before Terraform when the plan does not belong to this build') {
    // no plan produced in this build
    Map noPlan = applyEnv('true'); noPlan.remove('TF_PLAN_BUILD')
    def a = newStep('terraformApply', [env: noPlan,
                                       files: [(APPLY_INFO_PATH): APPLY_SIDECAR],
                                       missing: [APPLY_MARKER]])
    try {
        a.script.call(root: APPLY_ROOT)
        assert false: 'a missing plan handshake must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('no plan was produced in this build'): e.message
    }
    assert a.sh.isEmpty(): 'nothing must run without a plan of this build'

    // plan of another build
    def b = newStep('terraformApply', [env: applyEnv('true', [TF_PLAN_BUILD: '41']),
                                       files: [(APPLY_INFO_PATH): APPLY_SIDECAR],
                                       missing: [APPLY_MARKER]])
    try {
        b.script.call(root: APPLY_ROOT)
        assert false: 'a plan of another build must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('plan belongs to build 41'): e.message
    }
    assert b.sh.isEmpty()

    // plan of another root
    def c = newStep('terraformApply', [env: applyEnv('true', [TF_PLAN_ROOT: 'infra/terraform/envs/stage']),
                                       files: [(APPLY_INFO_PATH): APPLY_SIDECAR],
                                       missing: [APPLY_MARKER]])
    try {
        c.script.call(root: APPLY_ROOT)
        assert false: 'a plan of another root must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('refusing to apply the wrong plan'): e.message
    }
    assert c.sh.isEmpty()

    // plan file name mismatch
    def d = newStep('terraformApply', [env: applyEnv('true', [TF_PLAN_FILE: 'other.tfplan']),
                                       files: [(APPLY_INFO_PATH): APPLY_SIDECAR],
                                       missing: [APPLY_MARKER]])
    try {
        d.script.call(root: APPLY_ROOT)
        assert false: 'a mismatching plan name must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('refusing to apply'): e.message
    }
    assert d.sh.isEmpty()

    // invalid changes flag
    def e1 = newStep('terraformApply', [env: applyEnv('maybe'),
                                        files: [(APPLY_INFO_PATH): APPLY_SIDECAR],
                                        missing: [APPLY_MARKER]])
    try {
        e1.script.call(root: APPLY_ROOT)
        assert false: 'an invalid changes flag must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('invalid TF_PLAN_CHANGES'): e.message
    }
    assert e1.sh.isEmpty()

    // no GIT_COMMIT: the provenance cannot be verified
    def f = newStep('terraformApply', [env: applyEnv('true', [GIT_COMMIT: null]),
                                       files: [(APPLY_INFO_PATH): APPLY_SIDECAR],
                                       missing: [APPLY_MARKER]])
    try {
        f.script.call(root: APPLY_ROOT)
        assert false: 'a missing commit must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('GIT_COMMIT is not available'): e.message
    }
    assert f.sh.isEmpty()

    // plan file missing
    def g = newStep('terraformApply', [env: applyEnv('true'),
                                       files: [(APPLY_INFO_PATH): APPLY_SIDECAR],
                                       missing: [APPLY_PLAN_PATH, APPLY_MARKER]])
    try {
        g.script.call(root: APPLY_ROOT)
        assert false: 'a missing plan file must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('does not exist in the workspace'): e.message
    }
    assert g.sh.isEmpty()

    // sidecar missing
    def i = newStep('terraformApply', [env: applyEnv('true'),
                                       missing: [APPLY_INFO_PATH, APPLY_MARKER]])
    try {
        i.script.call(root: APPLY_ROOT)
        assert false: 'a missing sidecar must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('sidecar'): e.message
    }
    assert i.sh.isEmpty()

    // sidecar of another revision
    String otherCommit = APPLY_SIDECAR.replace('commit=abc1234', 'commit=deadbee')
    def j = newStep('terraformApply', [env: applyEnv('true'),
                                       files: [(APPLY_INFO_PATH): otherCommit],
                                       missing: [APPLY_MARKER]])
    try {
        j.script.call(root: APPLY_ROOT)
        assert false: 'a sidecar of another commit must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('another revision'): e.message
    }
    assert j.sh.isEmpty()

    // sidecar inconsistent with the handshake
    String otherChanges = APPLY_SIDECAR.replace('changes=true', 'changes=false')
    def k = newStep('terraformApply', [env: applyEnv('true'),
                                       files: [(APPLY_INFO_PATH): otherChanges],
                                       missing: [APPLY_MARKER]])
    try {
        k.script.call(root: APPLY_ROOT)
        assert false: 'an inconsistent sidecar must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('inconsistent plan state'): e.message
    }
    assert k.sh.isEmpty()
}

test('rejects a sidecar that belongs to another build') {
    String other = APPLY_SIDECAR.replace('build=42', 'build=41')
    def h = newStep('terraformApply', [env: applyEnv('true'),
                                       files: [(APPLY_INFO_PATH): other],
                                       missing: [APPLY_MARKER]])
    try {
        h.script.call(root: APPLY_ROOT)
        assert false: 'a sidecar of another build must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('the sidecar says build=41'): e.message
        assert e.message.contains('this is build 42'): e.message
    }
    assert h.sh.isEmpty(): 'it must fail before any command'
    assert h.withCredentials.isEmpty()
}

test('rejects a sidecar that belongs to another root') {
    String other = APPLY_SIDECAR.replace('root=infra/terraform/envs/dev',
                                         'root=infra/terraform/envs/stage')
    def h = newStep('terraformApply', [env: applyEnv('true'),
                                       files: [(APPLY_INFO_PATH): other],
                                       missing: [APPLY_MARKER]])
    try {
        h.script.call(root: APPLY_ROOT)
        assert false: 'a sidecar of another root must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('the sidecar says root=infra/terraform/envs/stage'): e.message
        assert e.message.contains('expected infra/terraform/envs/dev'): e.message
    }
    assert h.sh.isEmpty(): 'it must fail before any command'
    assert h.withCredentials.isEmpty()
}

test('rejects a sidecar path that differs from the one of the plan stage') {
    def h = newStep('terraformApply', [env: applyEnv('true', [TF_PLAN_INFO: 'other.tfplan.info']),
                                       files: [(APPLY_INFO_PATH): APPLY_SIDECAR],
                                       missing: [APPLY_MARKER]])
    try {
        h.script.call(root: APPLY_ROOT)
        assert false: 'a mismatching sidecar path must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('expected sidecar'): e.message
        assert e.message.contains('refusing to apply'): e.message
    }
    assert h.sh.isEmpty(): 'it must fail before any command'
    assert h.withCredentials.isEmpty()
}

test('rejects a sidecar whose status is not coherent with changes') {
    // changes=true requires status=2 (terraformPlan writes them together)
    String other = APPLY_SIDECAR.replace('status=2', 'status=0')
    def h = newStep('terraformApply', [env: applyEnv('true'),
                                       files: [(APPLY_INFO_PATH): other],
                                       missing: [APPLY_MARKER]])
    try {
        h.script.call(root: APPLY_ROOT)
        assert false: 'an incoherent status must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('status=0 but changes=true'): e.message
        assert e.message.contains('expected status=2'): e.message
    }
    assert h.sh.isEmpty(): 'it must fail before any command'
    assert h.withCredentials.isEmpty()
}

test('rejects a plan without a valid sha256 in the sidecar') {
    String other = APPLY_SIDECAR.replaceAll('sha256=[0-9a-f]{64}', 'sha256=none')
    def h = newStep('terraformApply', [env: applyEnv('true'),
                                       files: [(APPLY_INFO_PATH): other],
                                       missing: [APPLY_MARKER]])
    try {
        h.script.call(root: APPLY_ROOT)
        assert false: 'a sidecar without a hash must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('no valid sha256'): e.message
        assert e.message.contains('refusing to apply'): e.message
    }
    assert h.sh.isEmpty(): 'it must fail before any command'
    assert h.withCredentials.isEmpty()
}

test('refuses a plan whose sha256 does not match the sidecar') {
    def h = newStep('terraformApply', [env: applyEnv('true'),
                                       files: [(APPLY_INFO_PATH): APPLY_SIDECAR],
                                       missing: [APPLY_MARKER],
                                       stdout: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'])
    try {
        h.script.call(root: APPLY_ROOT)
        assert false: 'a modified plan must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('the plan changed after it was produced'): e.message
        assert e.message.contains(APPLY_SHA): e.message
    }
    // df + sha256sum: the hash is verified before anything touches AWS
    assert h.sh.size() == 2: "expected df + sha256sum, got ${h.sh.size()}"
    assert h.sh[0].startsWith('df -Pk')
    assert h.sh[1].startsWith('sha256sum')
    assert h.withCredentials.isEmpty(): 'the credential must not be bound'
    assert !h.sh.any { it.contains('docker run') }
}

test('fails closed when sha256sum is not available before applying') {
    def h = newStep('terraformApply', [env: applyEnv('true'),
                                       files: [(APPLY_INFO_PATH): APPLY_SIDECAR],
                                       missing: [APPLY_MARKER],
                                       failShContains: 'sha256sum'])
    try {
        h.script.call(root: APPLY_ROOT)
        assert false: 'without sha256sum nothing must be applied'
    } catch (RuntimeException e) {
        assert e.message.contains('sha256sum is required'): e.message
        assert e.message.contains('refusing to apply'): e.message
    }
    assert h.sh.size() == 2: 'df and the hash attempt only'
    assert h.withCredentials.isEmpty(): 'fail closed before the credential'
    assert !h.sh.any { it.contains('docker run') }
    assert !h.written.containsKey(APPLY_MARKER)
}

test('refuses to apply the same plan twice') {
    // the .applied marker already exists in the workspace
    def h = newStep('terraformApply', [env: applyEnv('true'),
                                       files: [(APPLY_INFO_PATH): APPLY_SIDECAR]])
    try {
        h.script.call(root: APPLY_ROOT)
        assert false: 'an already applied plan must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('already applied'): e.message
        assert e.message.contains('refusing to apply it twice'): e.message
    }
    assert h.sh.isEmpty(): 'nothing must run for an already applied plan'
    assert h.withCredentials.isEmpty()
}

test('keeps the original failure of a failed apply and never marks it as applied') {
    def h = newStep('terraformApply', [env: applyEnv('true'),
                                       files: [(APPLY_INFO_PATH): APPLY_SIDECAR],
                                       missing: [APPLY_MARKER],
                                       stdout: APPLY_SHA,
                                       failShContains: ' apply '])
    try {
        h.script.call(root: APPLY_ROOT)
        assert false: 'a failing apply must fail the step'
    } catch (RuntimeException e) {
        // the original cause is preserved (rethrown unchanged)
        assert e.message.contains('simulated command failure'): e.message
    }
    assert h.logs.any { it.contains('the apply of infra/terraform/envs/dev failed') }: h.logs
    // a generic failure is NOT an AccessDenied: the guidance must not be echoed
    assert h.logs.every { !it.contains('do NOT widen the IAM policies') }: h.logs
    assert !h.written.containsKey(APPLY_MARKER): 'a failed apply must not be marked'
    assert h.archived.isEmpty(): 'no evidence for a failed apply'
    assert !h.sh.any { it.startsWith('rm -f') }: 'the plan must survive a failure'
    assert h.sh.count { it.contains(' apply ') } == 1: 'no automatic retry'
}

test('reports explicitly when the evidence cannot be written after a successful apply') {
    def h = newStep('terraformApply', [env: applyEnv('true'),
                                       files: [(APPLY_INFO_PATH): APPLY_SIDECAR],
                                       missing: [APPLY_MARKER],
                                       stdout: APPLY_SHA,
                                       failWriteFileContains: 'terraform-apply-'])
    try {
        h.script.call(root: APPLY_ROOT)
        assert false: 'a failing evidence must fail the step'
    } catch (RuntimeException e) {
        assert e.message.contains('SUCCEEDED'): e.message
        assert e.message.contains('INFRASTRUCTURE MAY HAVE CHANGED'): e.message
        assert e.message.contains('could NOT be written'): e.message
        assert e.message.contains('Do NOT re-run automatically'): e.message
    }
    // the marker is written FIRST, so a re-run can never apply the plan again
    assert h.written.containsKey(APPLY_MARKER): 'the marker must precede the evidence'
    assert h.archived.isEmpty(): 'no evidence archived'
    assert !h.sh.any { it.startsWith('rm -f') }: 'the cleanup must not run after it'
    assert h.sh.count { it.contains(' apply ') } == 1: 'no automatic retry'
}

test('reports explicitly when the cleanup fails after a successful apply') {
    def h = newStep('terraformApply', [env: applyEnv('true'),
                                       files: [(APPLY_INFO_PATH): APPLY_SIDECAR],
                                       missing: [APPLY_MARKER],
                                       stdout: APPLY_SHA,
                                       failShContains: 'rm -f'])
    try {
        h.script.call(root: APPLY_ROOT)
        assert false: 'a failing cleanup must fail the step'
    } catch (RuntimeException e) {
        assert e.message.contains('SUCCEEDED'): e.message
        assert e.message.contains('Do NOT re-run automatically'): e.message
    }
    assert h.written.containsKey(APPLY_MARKER): 'the marker must be written first'
    assert h.archived == [APPLY_EVIDENCE]: 'the evidence must be archived before the cleanup'
    assert h.sh.count { it.contains(' apply ') } == 1: 'no automatic retry'
}

test('aborts before binding the credential when the disk is full') {
    def h = newStep('terraformApply', [env: applyEnv('true'),
                                       files: [(APPLY_INFO_PATH): APPLY_SIDECAR],
                                       missing: [APPLY_MARKER],
                                       dfOutput: LOW_DF])
    try {
        h.script.call(root: APPLY_ROOT)
        assert false: 'an insufficient disk must fail the step'
    } catch (RuntimeException e) {
        assert e.message.contains('97 MB free'): e.message
        assert e.message.contains('1500 MB required'): e.message
        assert e.message.contains('nothing was applied'): e.message
    }
    assert h.sh.size() == 1: 'only df may run'
    assert h.sh[0].startsWith('df -Pk')
    assert h.withCredentials.isEmpty(): 'the credential must not be bound'
    assert h.archived.isEmpty()
}

test('fails fast on an unsafe root, a missing root and an empty credential') {
    def noRoot = newStep('terraformApply')
    try {
        noRoot.script.call(root: null)
        assert false: 'a missing root must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('root is required'): e.message
    }
    assert noRoot.sh.isEmpty()

    def unsafe = newStep('terraformApply')
    try {
        unsafe.script.call(root: '../../etc')
        assert false: 'a root escaping the workspace must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('relative path'): e.message
    }
    assert unsafe.sh.isEmpty()

    def ghost = newStep('terraformApply', [missing: ['infra/terraform/envs/ghost']])
    try {
        ghost.script.call(root: 'infra/terraform/envs/ghost')
        assert false: 'a missing root must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('does not exist'): e.message
    }
    assert ghost.sh.isEmpty()

    def noVersions = newStep('terraformApply', [missing: ['infra/terraform/envs/dev/versions.tf']])
    try {
        noVersions.script.call(root: APPLY_ROOT)
        assert false: 'a root without versions.tf must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('versions.tf'): e.message
    }
    assert noVersions.sh.isEmpty()

    def noCredential = newStep('terraformApply')
    try {
        noCredential.script.call(root: APPLY_ROOT, credentialsId: '')
        assert false: 'an empty credential id must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('credentialsId is required'): e.message
    }
    assert noCredential.sh.isEmpty()

    def outside = newStep('terraformApply', [env: applyEnv('true', [
        WORKSPACE: '/var/jenkins_home/secrets'])])
    try {
        outside.script.call(root: APPLY_ROOT)
        assert false: 'a workspace outside workspace/ must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('not under /var/jenkins_home/workspace'): e.message
    }
    assert outside.sh.isEmpty()
}

test('never disables the lock, never auto-approves and never retries (source level)') {
    String step = new File(root, 'vars/terraformApply.groovy').text
    String applyLine = step.readLines().find { it.contains('command: "apply') }
    String initLine = step.readLines().find { it.contains("command: 'init") }

    assert applyLine != null: 'the apply command must be built'
    assert applyLine.contains('-lock=true'): applyLine
    assert !applyLine.contains('-lock=false'): 'the lock must never be disabled'
    assert !applyLine.contains('-auto-approve'): 'no -auto-approve'
    assert !applyLine.contains('-destroy'): 'no -destroy'
    assert !applyLine.contains('-replace'): 'no -replace'
    assert !step.contains('retry('): 'no automatic retry'
    assert !step.contains('terraform output'): 'no output is echoed'
    assert step.contains('throw e'): 'the original failure must be rethrown'
    assert step.contains('SKIPPED_NO_CHANGES')
    assert step.contains("usernameVariable: 'AWS_ACCESS_KEY_ID'")
    assert step.contains("passwordVariable: 'AWS_SECRET_ACCESS_KEY'")
    assert initLine != null && initLine.contains('-backend=true'): initLine
    assert !initLine.contains('-reconfigure') && !initLine.contains('-migrate-state')
}

test('reports explicitly when the marker cannot be written after a successful apply') {
    def h = newStep('terraformApply', [env: applyEnv('true'),
                                       files: [(APPLY_INFO_PATH): APPLY_SIDECAR],
                                       missing: [APPLY_MARKER],
                                       stdout: APPLY_SHA,
                                       failWriteFileContains: '.applied'])
    try {
        h.script.call(root: APPLY_ROOT)
        assert false: 'a failing marker must fail the step'
    } catch (RuntimeException e) {
        assert e.message.contains('SUCCEEDED'): e.message
        assert e.message.contains('INFRASTRUCTURE MAY HAVE CHANGED'): e.message
        assert e.message.contains('marker could not be written'): e.message
        assert e.message.contains('Do NOT re-run automatically'): e.message
    }
    assert !h.written.containsKey(APPLY_MARKER)
    assert h.written[APPLY_EVIDENCE] == null: 'the evidence comes after the marker'
    assert h.archived.isEmpty(): 'nothing archived'
    assert !h.sh.any { it.startsWith('rm -f') }: 'the cleanup must not run'
    assert h.sh.count { it.contains(' apply ') } == 1: 'no automatic retry'
}

test('reports explicitly when the evidence is written but cannot be archived') {
    def h = newStep('terraformApply', [env: applyEnv('true'),
                                       files: [(APPLY_INFO_PATH): APPLY_SIDECAR],
                                       missing: [APPLY_MARKER],
                                       stdout: APPLY_SHA,
                                       failArchiveContains: 'terraform-apply-'])
    try {
        h.script.call(root: APPLY_ROOT)
        assert false: 'a failing archive must fail the step'
    } catch (RuntimeException e) {
        assert e.message.contains('WAS written'): e.message
        assert e.message.contains('could NOT be archived'): e.message
        assert e.message.contains('Do NOT re-run automatically'): e.message
        // and it is NOT the "could not be written" message
        assert !e.message.contains('could NOT be written'): e.message
    }
    assert h.written.containsKey(APPLY_MARKER): 'the marker must be written first'
    assert h.written[APPLY_EVIDENCE] != null: 'the evidence exists in the workspace'
    assert h.archived.isEmpty(): 'nothing archived'
    assert !h.sh.any { it.startsWith('rm -f') }: 'the cleanup must not run'
    assert h.sh.count { it.contains(' apply ') } == 1: 'no automatic retry'
}

test('shows the AccessDenied guidance only for an AccessDenied failure') {
    def h = newStep('terraformApply', [env: applyEnv('true'),
                                       files: [(APPLY_INFO_PATH): APPLY_SIDECAR],
                                       missing: [APPLY_MARKER],
                                       stdout: APPLY_SHA,
                                       failShContains: ' apply ',
                                       failShMessage: 'simulated AccessDenied for ec2:RunInstances'])
    try {
        h.script.call(root: APPLY_ROOT)
        assert false: 'a failing apply must fail the step'
    } catch (RuntimeException e) {
        // the original exception is preserved, unchanged
        assert e.message.contains('simulated AccessDenied for ec2:RunInstances'): e.message
    }
    assert h.logs.any { it.contains('the apply of infra/terraform/envs/dev failed') }: h.logs
    assert h.logs.any { it.contains('do NOT widen the IAM policies') }:
        'the guidance must be echoed for an AccessDenied'
    assert !h.written.containsKey(APPLY_MARKER): 'a failed apply is never marked'
}

println 'trivyImageScan'
String IMG_REF = 'localhost:8082/circleguard/auth-service:1.2.0-build.42.ab12cd3'
String IMG_REPORT = 'trivy-image-report-42-localhost-8082-circleguard-auth-service-' +
                    '1-2-0-build-42-ab12cd3.txt'

test('scans the local image through the socket and blocks HIGH/CRITICAL') {
    def h = newStep('trivyImageScan', [files: [(IMG_REPORT): 'report body']])
    def result = h.script.call(ref: IMG_REF)

    // rm of a possible previous report + a single docker run
    assert h.sh.size() == 2: "expected 2 commands, got ${h.sh.size()}"
    assert h.sh[0] == "rm -f \"${IMG_REPORT}\"": h.sh[0]
    String cmd = h.sh[1]
    assert cmd.contains('docker run --rm')
    assert cmd.contains('--user $(id -u):$(id -g)')
    assert cmd.contains('-e HOME=/tmp')

    // the workspace is mounted with volume-subpath, the daemon through the socket
    assert cmd.contains("--mount 'type=volume,source=circleguard-jenkins-home," +
                        "destination=/ws,volume-subpath=workspace/circleguard_dev'")
    assert cmd.contains("--mount 'type=bind,source=/var/run/docker.sock," +
                        "destination=/var/run/docker.sock'")
    assert cmd.contains('-w /ws')
    assert !cmd.contains('/var/jenkins_home'): 'no host path may reach the container'

    // pinned tool image, blocking threshold, local-only resolution, shared cache
    assert cmd.contains('aquasec/trivy:0.76.2 image --severity HIGH,CRITICAL ' +
                        '--exit-code 1 --pull never')
    assert cmd.contains("--format table --output ${IMG_REPORT} --cache-dir /ws/.trivy-cache --quiet")
    assert cmd.contains('--ignorefile .trivyignore.yaml')
    assert cmd.endsWith(" ${IMG_REF}"): cmd

    // no push, no registry credential, no AWS credential in this container
    assert !cmd.contains('docker push')
    assert !cmd.contains('REGISTRY_PASS')
    assert !cmd.contains('-e AWS_')
    assert !cmd.contains('latest')

    // both mounts are separate shell words (regression: unknown flag: --mount type)
    List<String> tokens = tokenizeShell(cmd)
    List<Integer> mounts = []
    tokens.eachWithIndex { String t, int i -> if (t == '--mount') { mounts << i } }
    assert mounts.size() == 2: "two --mount flags expected: ${tokens}"
    assert !tokens.any { it.startsWith('--mount ') }
    assert tokens[mounts[0] + 1].startsWith('type=volume,source=circleguard-jenkins-home,'):
        tokens[mounts[0] + 1]
    assert tokens[mounts[0] + 1].contains('volume-subpath=workspace/circleguard_dev'):
        tokens[mounts[0] + 1]
    assert tokens[mounts[1] + 1] == 'type=bind,source=/var/run/docker.sock,destination=/var/run/docker.sock':
        tokens[mounts[1] + 1]

    // evidence: the report of THIS build is echoed and archived
    assert h.archived == [IMG_REPORT]: h.archived
    assert h.logs.any { it.contains('report body') }: h.logs
    assert result.ref == IMG_REF
    assert result.report == IMG_REPORT
    assert result.status == 0
    assert h.logs.any { it.contains('no HIGH,CRITICAL vulnerabilities') }: h.logs
}

test('blocks the build on findings and keeps the report as evidence') {
    def h = newStep('trivyImageScan', [status: 1, files: [(IMG_REPORT): 'CRITICAL CVE-2026-1234']])
    try {
        h.script.call(ref: IMG_REF)
        assert false: 'findings must fail the step'
    } catch (RuntimeException e) {
        assert e.message.contains('HIGH,CRITICAL vulnerabilities in localhost:8082'): e.message
        assert e.message.contains('.trivyignore.yaml'): 'the message must point to the ignore file'
        assert e.message.contains("Report archived: ${IMG_REPORT}"): e.message
    }
    assert h.archived == [IMG_REPORT]: 'the report must survive the failure'
    assert h.logs.any { it.contains('CRITICAL CVE-2026-1234') }: "the report must be echoed: ${h.logs}"
}

test('reports a scan error when no report was generated') {
    def h = newStep('trivyImageScan', [status: 1, missing: [IMG_REPORT]])
    try {
        h.script.call(ref: IMG_REF)
        assert false: 'a failing scan must fail the step'
    } catch (RuntimeException e) {
        assert e.message.contains('no report was generated'): e.message
        assert !e.message.contains('Report archived'): e.message
    }
    assert h.archived.isEmpty(): 'no stale report may be archived'
}

test('never archives the report of a previous build as evidence') {
    String old = IMG_REPORT.replace('trivy-image-report-42-', 'trivy-image-report-41-')
    def h = newStep('trivyImageScan', [status: 1,
                                       files: [(old): 'OLD EVIDENCE'],
                                       missing: [IMG_REPORT]])
    try {
        h.script.call(ref: IMG_REF)
        assert false: 'the step must fail'
    } catch (RuntimeException e) {
        assert !e.message.contains('Report archived'): e.message
    }
    assert h.archived.isEmpty(): 'the report of build 41 must not be archived for build 42'
    assert h.logs.every { !it.contains('OLD EVIDENCE') }
}

test('passes the ignore file only when it exists') {
    def present = newStep('trivyImageScan')
    present.script.call(ref: IMG_REF)
    assert present.sh[1].contains('--ignorefile .trivyignore.yaml')

    def absent = newStep('trivyImageScan', [missing: ['.trivyignore.yaml']])
    absent.script.call(ref: IMG_REF)
    assert !absent.sh[1].contains('--ignorefile'): 'no ignore file, no flag'
}

test('fails fast on an invalid ref, an unpinned tool image and an unsafe workspace') {
    def noRef = newStep('trivyImageScan')
    try {
        noRef.script.call(ref: null)
        assert false: 'a missing ref must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('ref is required'): e.message
    }
    assert noRef.sh.isEmpty(): 'nothing must run without a ref'

    def unsafe = newStep('trivyImageScan')
    try {
        unsafe.script.call(ref: 'img; rm -rf /')
        assert false: 'an unsafe ref must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('invalid image reference'): e.message
    }
    assert unsafe.sh.isEmpty()

    def latest = newStep('trivyImageScan')
    try {
        latest.script.call(ref: IMG_REF, toolImage: 'aquasec/trivy:latest')
        assert false: ':latest must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('pinned'): e.message
    }
    assert latest.sh.isEmpty()

    def badIgnore = newStep('trivyImageScan')
    try {
        badIgnore.script.call(ref: IMG_REF, ignoreFile: '../secrets.yaml')
        assert false: 'an ignore file outside the workspace must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('plain file name'): e.message
    }
    assert badIgnore.sh.isEmpty()

    def outside = newStep('trivyImageScan', [env: [WORKSPACE: '/var/jenkins_home/secrets',
                                                   BUILD_NUMBER: '42']])
    try {
        outside.script.call(ref: IMG_REF)
        assert false: 'a workspace outside workspace/ must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('not under /var/jenkins_home/workspace'): e.message
    }
    assert outside.sh.isEmpty(): 'the container must not start outside the workspace'

    String ghost = '/var/jenkins_home/workspace/circleguard_ghost'
    def missing = newStep('trivyImageScan', [env: [WORKSPACE: ghost, BUILD_NUMBER: '42'],
                                             missing: [ghost]])
    try {
        missing.script.call(ref: IMG_REF)
        assert false: 'a missing workspace must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('does not exist yet'): e.message
    }
    assert missing.sh.isEmpty()
}

println 'publishImages'
Map ONE_IMAGE = [name: 'circleguard/auth-service', dockerfile: 'services/auth/Dockerfile', context: '.']

def publishOpts = { String branch ->
    Map env = [WORKSPACE: '/var/jenkins_home/workspace/circleguard_dev', BUILD_NUMBER: '42']
    if (branch != null) { env.BRANCH_NAME = branch }
    [env: env]
}

test('scans the local image between docker build and docker push') {
    def h = newStep('publishImages', publishOpts('dev'))
    h.script.call(registry: 'localhost:8082', version: '1.2.0', images: [ONE_IMAGE],
                  scanVulnerabilities: true, scanBranches: ['dev'])

    List t = h.trace
    int build = t.findIndexOf { it.contains('docker build') }
    int scan = t.findIndexOf { it.startsWith('trivyImageScan(') }
    int push = t.findIndexOf { it.contains('docker push') }
    int rm = t.findIndexOf { it.contains('docker image rm') }
    assert build > 0: "no build in ${t}"
    assert scan > build: "the scan must run after the build: ${t}"
    assert push > scan: "the push must run after the scan: ${t}"
    assert rm > push: "the local image is removed after the push: ${t}"

    assert t[0] == 'ensureBuildx()': t
    assert t[1] == 'dockerCleanup()': t
    assert t[scan] == 'trivyImageScan(localhost:8082/circleguard/auth-service:1.2.0)': t
    assert t.any { it.contains('docker login') }
    assert t.any { it.contains('docker logout') }
    assert h.archived.contains('published-images.txt')
    // the scan receives the same ref that is built and pushed
    assert t[build].contains("-t 'localhost:8082/circleguard/auth-service:1.2.0'"): t[build]
    assert t[push].contains("docker push 'localhost:8082/circleguard/auth-service:1.2.0'"): t[push]
}

test('does not scan when the feature is disabled (default)') {
    def h = newStep('publishImages', publishOpts('dev'))
    h.script.call(registry: 'localhost:8082', version: '1.2.0', images: [ONE_IMAGE])

    assert h.trace.every { !it.startsWith('trivyImageScan(') }: h.trace
    assert h.trace.any { it.contains('docker build') }
    assert h.trace.any { it.contains('docker push') }
    assert h.archived.contains('published-images.txt')
}

test('scans only the configured branches') {
    // branch outside the list: no scan
    def main = newStep('publishImages', publishOpts('main'))
    main.script.call(registry: 'localhost:8082', version: '1.2.0', images: [ONE_IMAGE],
                     scanVulnerabilities: true, scanBranches: ['dev'])
    assert main.trace.every { !it.startsWith('trivyImageScan(') }: main.trace
    assert main.trace.any { it.contains('docker push') }

    // branch inside the list: scan
    def dev = newStep('publishImages', publishOpts('dev'))
    dev.script.call(registry: 'localhost:8082', version: '1.2.0', images: [ONE_IMAGE],
                    scanVulnerabilities: true, scanBranches: ['dev'])
    assert dev.trace.any { it.startsWith('trivyImageScan(') }: dev.trace
}

test('skips the scan when the branch is unknown (no BRANCH_NAME)') {
    // env without BRANCH_NAME: the scan must be skipped, the publication continues
    def h = newStep('publishImages', publishOpts(null))
    h.script.call(registry: 'localhost:8082', version: '1.2.0', images: [ONE_IMAGE],
                  scanVulnerabilities: true, scanBranches: ['dev'])

    assert h.trace.every { !it.startsWith('trivyImageScan(') }: h.trace
    assert h.trace.any { it.contains('docker build') }
    assert h.trace.any { it.contains('docker push') }
    assert h.archived.contains('published-images.txt')
}

test('a failing scan prevents the push and still logs out of the registry') {
    def h = newStep('publishImages', [failScan: true,
        env: [WORKSPACE: '/var/jenkins_home/workspace/circleguard_dev',
              BUILD_NUMBER: '42', BRANCH_NAME: 'dev']])
    try {
        h.script.call(registry: 'localhost:8082', version: '1.2.0', images: [ONE_IMAGE],
                      scanVulnerabilities: true, scanBranches: ['dev'])
        assert false: 'a failing scan must fail the publication'
    } catch (RuntimeException e) {
        assert e.message.contains('simulated image scan failure'): e.message
    }

    List t = h.trace
    assert t.any { it.contains('docker build') }: 'the image must be built first'
    assert t.any { it.startsWith('trivyImageScan(') }: 'the scan must run'
    assert !t.any { it.contains('docker push') }: 'a vulnerable image must not be pushed'
    assert !t.any { it.contains('docker image rm') }: 'the image stays for the diagnosis'
    assert t.any { it.contains('docker logout') }: 'the registry session must be closed'
    assert h.archived.isEmpty(): 'published-images.txt must not be archived'
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

test('keeps Trivy Image off by default and documents the tool image') {
    def cls = loader.parseClass(new File(root, 'src/org/circleguard/ci/PipelineConfig.groovy'))
    def cfg = cls.getConstructor(Map).newInstance([:])

    assert cfg.trivyImageScan == false: 'the image scan must be off by default'
    assert cfg.trivyImageSeverity == 'HIGH,CRITICAL': cfg.trivyImageSeverity
    assert cfg.trivyImageBranches == ['dev', 'main']: cfg.trivyImageBranches
    assert cfg.trivyImageTimeout > 0
    assert cfg.trivyImageIgnoreFile == '.trivyignore.yaml'
    assert cfg.trivyScan == false: 'the IaC scan stays off by default too'

    // `trivyImage` is the image of the Trivy TOOL (the scanner), never the image
    // that gets scanned: it must be pinned and it is shared by both scans.
    assert cfg.trivyImage == 'aquasec/trivy:0.76.2': cfg.trivyImage
    assert cfg.trivyImage.contains(':') && !cfg.trivyImage.endsWith(':latest')
}

test('accepts the Trivy Image parameters from the Jenkinsfile') {
    def cls = loader.parseClass(new File(root, 'src/org/circleguard/ci/PipelineConfig.groovy'))
    def cfg = cls.getConstructor(Map).newInstance(
        [trivyImageScan: true,
         trivyImageSeverity: 'CRITICAL',
         trivyImageBranches: ['dev'],
         trivyImageTimeout: 30,
         trivyImageIgnoreFile: '.trivyignore'])

    assert cfg.trivyImageScan == true
    assert cfg.trivyImageSeverity == 'CRITICAL'
    assert cfg.trivyImageBranches == ['dev']
    assert cfg.trivyImageTimeout == 30
    assert cfg.trivyImageIgnoreFile == '.trivyignore'
    // untouched defaults keep their value
    assert cfg.trivyImage == 'aquasec/trivy:0.76.2'
    assert cfg.trivySeverity == 'HIGH,CRITICAL'
}

test('keeps Terraform apply off by default, DEV only and behind the same flag') {
    def cls = loader.parseClass(new File(root, 'src/org/circleguard/ci/PipelineConfig.groovy'))
    def cfg = cls.getConstructor(Map).newInstance([:])

    assert cfg.terraformApply == false: 'the apply stage must be off by default'
    assert cfg.terraformApplyRoot == 'infra/terraform/envs/dev': cfg.terraformApplyRoot
    assert cfg.terraformApplyBranches == ['dev']: cfg.terraformApplyBranches
    assert cfg.terraformApplyTimeout > 0
    // plan and apply are separate switches: nothing runs without both
    assert cfg.terraformPlan == false
    assert cfg.terraformPlanRoot == 'infra/terraform/envs/dev'
}

test('accepts the Terraform apply parameters from the Jenkinsfile') {
    def cls = loader.parseClass(new File(root, 'src/org/circleguard/ci/PipelineConfig.groovy'))
    def cfg = cls.getConstructor(Map).newInstance(
        [terraformApply: true,
         terraformApplyRoot: 'infra/terraform/envs/stage',
         terraformApplyBranches: ['main'],
         terraformApplyTimeout: 45])

    assert cfg.terraformApply == true
    assert cfg.terraformApplyRoot == 'infra/terraform/envs/stage'
    assert cfg.terraformApplyBranches == ['main']
    assert cfg.terraformApplyTimeout == 45
    // untouched defaults keep their value
    assert cfg.terraformPlan == false
    assert cfg.terraformAwsCredentialsId == 'aws-terraform-credentials'
    assert cfg.terraformImage == 'hashicorp/terraform:1.17.2'
}

println 'circleguardPipeline (integration, source level)'
test('still compiles with the new stages') {
    // a child loader so that PipelineConfig is visible to the import of the entry point
    def child = new GroovyClassLoader(loader)
    child.parseClass(new File(root, 'src/org/circleguard/ci/PipelineConfig.groovy'))
    child.parseClass(new File(root, 'vars/circleguardPipeline.groovy'))
    child.parseClass(new File(root, 'vars/terraformValidate.groovy'))
    child.parseClass(new File(root, 'vars/terraformPlan.groovy'))
    child.parseClass(new File(root, 'vars/terraformApply.groovy'))
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

    String block = text.substring(plan, text.indexOf("stage('Terraform apply')"))
    // flag AND branch: PRs and every other branch are excluded from the credential
    assert block.contains('cfg.terraformPlan && cfg.terraformPlanBranches.contains(env.BRANCH_NAME)')
    assert block.contains('timeout(time: cfg.terraformPlanTimeout')
    assert block.contains('root: cfg.terraformPlanRoot')
    assert block.contains('credentialsId: cfg.terraformAwsCredentialsId')
    assert block.contains('region: cfg.terraformAwsRegion')
    assert block.contains('minFreeSpaceMB: cfg.terraformMinFreeSpaceMB')
    assert !block.contains('terraformApply'): 'apply is not part of this phase'
}

test('passes the Trivy Image configuration to publishImages') {
    String text = new File(root, 'vars/circleguardPipeline.groovy').text
    assert text.contains('scanVulnerabilities: cfg.trivyImageScan')
    assert text.contains('trivyToolImage: cfg.trivyImage')
    assert text.contains('scanSeverity: cfg.trivyImageSeverity')
    assert text.contains('scanTimeout: cfg.trivyImageTimeout')
    assert text.contains('scanBranches: cfg.trivyImageBranches')
    assert text.contains('scanIgnoreFile: cfg.trivyImageIgnoreFile')

    // the publish stage keeps its own branch gate: PRs never reach the scan
    int publish = text.indexOf("stage('Publish images')")
    int deploy = text.indexOf("stage('Deploy')")
    assert publish > 0 && deploy > publish
    String stage = text.substring(publish, deploy)
    assert stage.contains('cfg.publish && cfg.publishBranches.contains(env.BRANCH_NAME)')
}

test('persists the plan result and applies it after the plan, before Publish images') {
    String text = new File(root, 'vars/circleguardPipeline.groovy').text

    // the result of the plan stage is persisted for the apply stage
    assert text.contains('Map plan = terraformPlan('): 'the plan result must be captured'
    assert text.contains('env.TF_PLAN_BUILD = env.BUILD_NUMBER')
    assert text.contains('env.TF_PLAN_ROOT = plan.root')
    assert text.contains('env.TF_PLAN_FILE = plan.planFile')
    assert text.contains('env.TF_PLAN_INFO = plan.planInfo')
    assert text.contains('env.TF_PLAN_CHANGES = plan.changes.toString()')

    int plan = text.indexOf("stage('Terraform plan')")
    int apply = text.indexOf("stage('Terraform apply')")
    int publish = text.indexOf("stage('Publish images')")
    assert plan > 0 && apply > plan && publish > apply:
        "wrong order: plan=${plan} apply=${apply} publish=${publish}"

    String block = text.substring(apply, publish)
    // flag AND branch: PRs never receive the AWS credential
    assert block.contains('cfg.terraformApply && cfg.terraformApplyBranches.contains(env.BRANCH_NAME)')
    // stage budget is 2x the command timeout; the whole build gets 120 minutes
    assert block.contains('timeout(time: cfg.terraformApplyTimeout * 2, unit:')
    assert text.contains("timeout(time: 120, unit: 'MINUTES')")
    assert block.contains('root: cfg.terraformApplyRoot')
    assert block.contains('credentialsId: cfg.terraformAwsCredentialsId')
    assert block.contains('region: cfg.terraformAwsRegion')
    assert block.contains('timeout: cfg.terraformApplyTimeout')
    assert block.contains('minFreeSpaceMB: cfg.terraformMinFreeSpaceMB')
}

test('queues builds instead of aborting the one in progress') {
    String text = new File(root, 'vars/circleguardPipeline.groovy').text
    assert text.contains('disableConcurrentBuilds()'): 'builds must queue'
    assert !text.contains('abortPrevious'):
        'a running apply or approval must never be cancelled by a new build'

    // the step that could be interrupted documents the queued behaviour too
    String apply = new File(root, 'vars/terraformApply.groovy').text
    assert apply.contains('disableConcurrentBuilds()'): 'the step must document the queue'
    assert !apply.contains('abortPrevious: true'):
        'terraformApply must not reference the aborting option'

    // and the README explains the operational implications
    String readme = new File(root, 'README.md').text
    assert readme.contains('Concurrency: builds queue'): 'the section must exist'
    assert readme.contains('waits in the queue'): 'the queued behaviour must be explained'
}

test('the apply stage is opt-in: off by default and gated by flag and branch') {
    String text = new File(root, 'vars/circleguardPipeline.groovy').text
    assert text.contains("stage('Terraform apply')"): 'the apply stage must exist'
    assert text.contains('cfg.terraformApply && cfg.terraformApplyBranches.contains(env.BRANCH_NAME)'):
        'the apply stage must be gated by flag AND branch'
    assert new File(root, 'vars/terraformApply.groovy').exists(): 'the apply step must exist'
}

test('keeps every pre-existing stage') {
    String text = new File(root, 'vars/circleguardPipeline.groovy').text
    ['Checkout', 'Build', 'Tests', 'Integration tests', 'SonarQube', 'Publish images',
     'Deploy', 'Verify deployment', 'Smoke tests', 'E2E tests',
     'Promote to stage', 'Promote to prod'].each { String stage ->
        assert text.contains("stage('${stage}')"): "stage ${stage} disappeared"
    }
    assert text.contains('disableConcurrentBuilds()'): 'builds must queue, not abort'
    assert !text.contains('abortPrevious'):
        'abortPrevious must never cancel a running build or approval'
}

println 'runE2E'
test('mounts only the job workspace with volume-subpath and keeps the reports') {
    def h = newStep('runE2E')
    h.script.call(baseUrl: 'http://44.212.47.173:8081')

    // only one command: the docker run (no df, no mkdir, no rm)
    assert h.sh.size() == 1: "expected 1 command, got ${h.sh.size()}"
    String cmd = h.sh[0]
    assert cmd.contains('docker run --rm')

    // H1: ONLY the workspace of the job is mounted, with the same pattern as
    // runInContainer; the whole volume and any host path stay out of the container
    assert cmd.contains("--mount 'type=volume,source=circleguard-jenkins-home," +
                        "destination=/jh,volume-subpath=workspace/circleguard_dev'")
    assert !cmd.contains('-v circleguard-jenkins-home'): 'the whole volume must not be mounted'
    assert !cmd.contains('-v ${volume}'): 'the whole volume must not be mounted'
    assert !cmd.contains('/var/jenkins_home'): 'no host path may reach the container'
    assert !cmd.contains('/var/lib/docker'): 'no host path may reach the container'
    assert cmd.contains('-w /jh/tests/e2e-playwright')

    // tokenisation: `--mount` and its value must be separate shell words
    // (regression for `unknown flag: --mount type`)
    List<String> tokens = tokenizeShell(cmd)
    int mount = tokens.indexOf('--mount')
    assert mount > 0: "the --mount flag must be its own token: ${tokens}"
    assert !tokens.any { it.startsWith('--mount ') }: "the flag must not carry its value: ${tokens}"
    assert tokens[mount + 1].startsWith('type=volume,source=circleguard-jenkins-home'): tokens[mount + 1]
    assert tokens[mount + 1].contains('volume-subpath=workspace/circleguard_dev'): tokens[mount + 1]
    int w = tokens.indexOf('-w')
    assert w > 0 && tokens[w + 1] == '/jh/tests/e2e-playwright': "wrong -w token: ${tokens}"

    // everything else is unchanged: uid, HOME, pinned image, Playwright command
    assert cmd.contains('--user "$(id -u):$(id -g)"')
    assert cmd.contains('-e HOME=/tmp')
    assert cmd.contains('mcr.microsoft.com/playwright:v1.65.0-noble')
    assert cmd.contains("bash -c 'npm ci && npx playwright test'")
    // ... and the image is the one that runs the Playwright command
    int img = tokens.indexOf('mcr.microsoft.com/playwright:v1.65.0-noble')
    assert img > 0: "the pinned image must be in the command: ${tokens}"
    assert tokens[img + 1] == 'bash' && tokens[img + 2] == '-c':
        "the image must run the Playwright command: ${tokens[img..-1]}"
    assert cmd.contains("-e BASE_URL='http://44.212.47.173:8081'")

    // credentials are bound once, by name only (no value in the command)
    assert h.withCredentials.size() == 1
    Map cred = h.withCredentials[0][0]
    assert cred.credentialsId == 'e2e-credential': cred
    assert cred.usernameVariable == 'E2E_USERNAME': cred
    assert cred.passwordVariable == 'E2E_PASSWORD': cred
    assert cmd.contains('-e E2E_USERNAME') && !cmd.contains('-e E2E_USERNAME=')
    assert cmd.contains('-e E2E_PASSWORD') && !cmd.contains('-e E2E_PASSWORD=')
    assert cmd.contains('-e CI=true')

    // the reports are still published with the usual paths
    assert h.junit == ['tests/e2e-playwright/results.xml']: h.junit
    assert h.archived.contains('tests/e2e-playwright/playwright-report/**, ' +
                               'tests/e2e-playwright/test-results/**'): h.archived
}

test('publishes the reports even when the container fails') {
    def h = newStep('runE2E', [failSh: true])
    try {
        h.script.call(baseUrl: 'http://44.212.47.173:8081')
        assert false: 'a failing container must fail the step'
    } catch (RuntimeException e) {
        assert e.message.contains('simulated command failure'): e.message
    }
    // the `finally` block ran before the failure propagated
    assert h.junit == ['tests/e2e-playwright/results.xml']: h.junit
    assert h.archived.contains('tests/e2e-playwright/playwright-report/**, ' +
                               'tests/e2e-playwright/test-results/**'): h.archived
}

test('refuses a workspace outside /var/jenkins_home/workspace before running') {
    def h = newStep('runE2E', [env: [WORKSPACE: '/var/jenkins_home/secrets',
                                      BUILD_NUMBER: '42']])
    try {
        h.script.call(baseUrl: 'http://44.212.47.173:8081')
        assert false: 'a workspace outside workspace/ must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('not under /var/jenkins_home/workspace'): e.message
    }
    assert h.sh.isEmpty(): 'nothing must run when the workspace is not isolated'
    assert h.withCredentials.isEmpty(): 'the credential must not be bound'
    assert h.junit.isEmpty()
}

test('refuses to mount a workspace that does not exist yet') {
    String ghost = '/var/jenkins_home/workspace/circleguard_ghost'
    def h = newStep('runE2E', [env: [WORKSPACE: ghost, BUILD_NUMBER: '42'],
                               missing: [ghost]])
    try {
        h.script.call(baseUrl: 'http://44.212.47.173:8081')
        assert false: 'a missing workspace must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('does not exist yet'): e.message
        assert e.message.contains('Checkout'): e.message
    }
    assert h.sh.isEmpty(): 'the container must not start with a missing subpath'
    assert h.withCredentials.isEmpty()
}

test('no step mounts the whole Jenkins volume anymore (source level)') {
    File[] steps = new File(root, 'vars').listFiles()
    steps.findAll { it.name.endsWith('.groovy') }.each { File f ->
        String text = f.text
        assert !text.contains('-v ${volume}:'):
            "${f.name} still mounts the whole volume"
    }
    String e2e = new File(root, 'vars/runE2E.groovy').text
    assert e2e.contains('volume-subpath'): 'runE2E must use volume-subpath'
    assert e2e.contains('fileExists(env.WORKSPACE)'): 'runE2E must guard the mount'
    assert !e2e.contains('hostWorkspace'): 'the whole-volume path translation is gone'
}

test('documents the image scan in the READMEs') {
    String readme = new File(root, 'README.md').text
    assert readme.contains('| `trivyImageScan` |'): 'the parameter must be documented'
    assert readme.contains('| `trivyImageSeverity` |')
    assert readme.contains('| `trivyImageBranches` |')
    assert readme.contains('| `trivyImageIgnoreFile` |')
    assert readme.contains('Trivy **tool**'): 'the meaning of trivyImage must be documented'
    assert readme.contains('## Image vulnerabilities (Trivy Image)'): 'the section must exist'

    String testReadme = new File(root, 'test/README.md').text
    assert testReadme.contains('| `trivyImageScan` |'): 'the step must be covered'
    assert testReadme.contains('| `publishImages` |'): 'publishImages coverage must be documented'
}

test('documents the terraform apply step in the READMEs') {
    String readme = new File(root, 'README.md').text
    assert readme.contains('| `terraformApply` |'): 'the parameter must be documented'
    assert readme.contains('| `terraformApplyRoot` |')
    assert readme.contains('| `terraformApplyBranches` |')
    assert readme.contains('| `terraformApplyTimeout` |')
    assert readme.contains('## Terraform apply (DEV only)'): 'the section must exist'
    assert readme.contains('disableConcurrentBuilds()'): 'the queued behaviour must be documented'
    assert readme.contains('abortPrevious'): 'the removed option must be documented'
    assert !readme.contains('disableConcurrentBuilds(abortPrevious: true)'):
        'the aborting configuration must no longer be documented as active'
    assert readme.contains('ci-<env>-b<build>.tfplan'): 'the plan naming must be documented'

    String testReadme = new File(root, 'test/README.md').text
    assert testReadme.contains('| `terraformApply` |'): 'the step must be covered'
    assert testReadme.contains('| `terraformPlan` |'): 'the plan row must be updated'
}

println ''
println "passed: ${passed}, failed: ${failures.size()}"
failures.each { println "  - ${it}" }
System.exit(failures.isEmpty() ? 0 : 1)
