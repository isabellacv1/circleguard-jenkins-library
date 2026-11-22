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

String VALID_K8S_MANIFEST = '''apiVersion: v1
kind: ConfigMap
metadata:
  name: circleguard-common-config
  namespace: circleguard
data:
  APP_ENV: dev
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: circleguard-web
  namespace: circleguard
'''

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
loader.parseClass('package com.cloudbees.groovy.cps; import java.lang.annotation.*; @Retention(RetentionPolicy.RUNTIME) @Target([ElementType.METHOD]) public @interface NonCPS {}')

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

def newTempDir = { String prefix ->
    return java.nio.file.Files.createTempDirectory(new File('/tmp/opencode').toPath(), prefix).toFile()
}

def writeTestFile = { File file, String text ->
    file.parentFile?.mkdirs()
    file.text = text
    return file
}

def fakeKubectl = { File dir ->
    File bin = new File(dir, 'bin')
    bin.mkdirs()
    File argvLog = new File(dir, 'argv.log')
    File script = new File(bin, 'kubectl')
    writeTestFile(script, '''#!/bin/bash
printf '%s\\n' "$*" >> "$ARGV_LOG"
case "$*" in
  *"config view"*) printf '%s' "$FAKE_KUBECONFIG_CONTENT" ;;
  *"config current-context"*) printf '%s\\n' "$K8S_CONTEXT" ;;
  *"config set-context"*)
    awk -v u="$K8S_KUBECONFIG_USER" -v c="$K8S_CONTEXT" '
      /^current-context:/ { print "current-context: " c; next }
      /^    user: / && !done { print "    user: " u; done = 1; next }
      { print }
    ' "$K8S_KUBECONFIG_FILE" > "$K8S_KUBECONFIG_FILE.ctx" && mv "$K8S_KUBECONFIG_FILE.ctx" "$K8S_KUBECONFIG_FILE"
    ;;
esac
exit 0
''')
    script.setExecutable(true)
    return [bin: bin, argvLog: argvLog]
}

def runShell = { String scriptText, File cwd, Map envVars = [:], String prependPath = null ->
    ProcessBuilder pb = new ProcessBuilder('bash', '-c', scriptText)
    pb.directory(cwd)
    pb.redirectErrorStream(true)
    Map processEnv = pb.environment()
    if (prependPath) {
        processEnv.PATH = prependPath + File.pathSeparator + (processEnv.PATH ?: '/usr/bin:/bin')
    }
    envVars.each { String key, Object value -> processEnv[key] = value.toString() }
    Process process = pb.start()
    String stdout = process.inputStream.getText('UTF-8')
    int exit = process.waitFor()
    return [stdout: stdout, exit: exit]
}

/**
 * Instantiates a step with a stubbed Jenkins environment.
 *
 * Returns a map with: script, sh (recorded commands), logs, archived, written
 * (file -> content written by the stubbed writeFile), withEnv,
 * withCredentials (the bindings recorded by the stubbed withCredentials),
 * junit (the testResults published by the stubbed junit), inputs (the maps
 * received by the stubbed input step) and trace (the ordered record of sh
 * commands plus the stubbed sibling steps: ensureBuildx, dockerCleanup,
 * trivyImageScan).
 * opts.status               exit code returned by sh(..., returnStatus: true)
 * opts.missing              paths for which fileExists() answers false
 * opts.files                contents returned by readFile()
 * opts.dfOutput             stdout of the `df` call (free-space check)
 * opts.renderedManifest     stdout of `kubectl kustomize` (defaults to a valid app render)
 * opts.failSh               when true, every sh throws (checks the `finally` evidence)
 * opts.failShMessage        message used by failSh / failShContains (e.g. AccessDenied)
 * opts.failShContains       every sh whose text contains this value throws
 * opts.failArchiveContains  archiveArtifacts throws for the files containing this value
 * opts.failWriteFileContains writeFile throws for the files whose name contains this value
 * opts.failScan             when true, the trivyImageScan stub throws (checks the push gate)
 * opts.inputResult          value returned by the stubbed input step ('admin' default)
 * opts.failInput            Throwable thrown by the stubbed input step (expired/cancelled)
 * opts.credentialValues     fake values bound by withCredentials, to detect leakage
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
        inputs  : [],        // maps passed to the stubbed input step
        currentBuild: [description: ''],
        shellOutputs: [],
        shellCodes: [],
        deployKubernetesParams: [],
        trace   : []     // ordered: sh commands + stubbed sibling steps (order assertions)
    ]
    def binding = new Binding()
    binding.setVariable('env', b.env)
    binding.setVariable('currentBuild', b.currentBuild)
    binding.setVariable('echo', { Object m -> b.logs << m.toString() })
    binding.setVariable('error', { Object m -> throw new RuntimeException(m.toString()) })
    binding.setVariable('sh', { Object arg ->
        String scriptText = (arg instanceof Map) ? arg.script.toString() : arg.toString()
        b.sh << scriptText
        b.trace << scriptText
        List<String> realPatterns = (opts.realShContains instanceof List) ?
                opts.realShContains.collect { it.toString() } :
                (opts.realShContains ? [opts.realShContains.toString()] : [])
        if (realPatterns.any { scriptText.contains(it) }) {
            File cwd = (opts.realShCwd ?: new File('/tmp/opencode')) as File
            def result = runShell(scriptText, cwd, (opts.realShEnv ?: [:]) as Map,
                                  opts.realShPath as String)
            b.shellOutputs << result.stdout
            b.shellCodes << result.exit
            if (arg instanceof Map && arg.returnStdout) {
                return result.stdout
            }
            if (result.exit != 0) {
                throw new RuntimeException("shell failed (${result.exit}): ${result.stdout.trim()}")
            }
            return result.exit
        }
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
        (opts.failShContainsList ?: []).each { Map failure ->
            if (scriptText.contains(failure.contains)) {
                throw new RuntimeException(failure.message ?: 'simulated command failure')
            }
        }
        if (arg instanceof Map) {
            if (arg.returnStatus) {
                return (opts.status ?: 0) as int
            }
            if (arg.returnStdout) {
                if (scriptText.startsWith('df ')) {
                    return (opts.dfOutput ?: ENOUGH_DF)
                }
                if (scriptText.contains('kubectl kustomize')) {
                    return (opts.renderedManifest ?: VALID_K8S_MANIFEST)
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
    // like the real step; credential helpers return their arguments, so a test can
    // assert ids and variable names WITHOUT reading any secret. Fake values are
    // injected into env only to detect accidental interpolation into logs.
    binding.setVariable('usernamePassword', { Object args -> args })
    binding.setVariable('file', { Object args -> args })
    binding.setVariable('string', { Object args -> args })
    binding.setVariable('withCredentials', { Object bindings, Closure body ->
        b.withCredentials << bindings
        Map previous = [:]
        List specs = (bindings instanceof List) ? bindings : [bindings]
        specs.each { Object spec ->
            if (spec instanceof Map && spec.variable != null) {
                String variable = spec.variable.toString()
                previous[variable] = b.env.containsKey(variable) ? b.env[variable] : null
                Object configured = (opts.credentialValues ?: [:])[variable]
                b.env[variable] = (configured ?: "FAKE_${variable}").toString()
            }
        }
        try {
            return body.call()
        } finally {
            previous.each { String variable, Object value ->
                if (value == null) {
                    b.env.remove(variable)
                } else {
                    b.env[variable] = value
                }
            }
        }
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
    // input: records every call (message, ok, submitter, submitterParameter,
    // timeout, timeUnit) and returns opts.inputResult ('admin' by default);
    // opts.failInput throws, simulating an expired or cancelled approval.
    binding.setVariable('input', { Object a ->
        b.inputs << (a instanceof Map ? a : [value: a])
        if (opts.failInput) {
            throw opts.failInput
        }
        return opts.containsKey('inputResult') ? opts.inputResult : 'admin'
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
    binding.setVariable('deployKubernetes', { Map p ->
        b.deployKubernetesParams << p
        b.trace << "deployKubernetes(${p.environment})"
        [manifestArtifact: "k8s/rendered-${p.environment}-${b.env.BUILD_NUMBER ?: 'local'}.yaml"]
    })
    binding.setVariable('verifyIngress', { Map p ->
        b.trace << "verifyIngress(${p.baseUrl})"
        []
    })
    binding.setVariable('smokeTests', { Map p ->
        b.trace << "smokeTests(${p.baseUrl})"
        []
    })

     [script: script, sh: b.sh, logs: b.logs, archived: b.archived, written: b.written,
      env: b.env, withEnv: b.withEnv, withCredentials: b.withCredentials, junit: b.junit,
      inputs: b.inputs, trace: b.trace, currentBuild: b.currentBuild,
      deployKubernetesParams: b.deployKubernetesParams,
      shellOutputs: b.shellOutputs, shellCodes: b.shellCodes]
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
test('checks the disk, creates the plugin cache and the data dirs, and runs fmt/init/validate, and nothing else') {
    def h = newStep('terraformValidate')
    h.script.call(roots: ['infra/terraform/envs/dev'], fmtPath: 'infra/terraform')

    // df (free space) + mkdir (plugin cache) + fmt + mkdir (data dir) + init + validate
    assert h.sh.size() == 6: "expected 6 commands, got ${h.sh.size()}"
    assert h.sh[0].startsWith('df -Pk'): 'the disk must be checked first'
    assert h.sh[1].contains('.terraform-plugin-cache'): 'the plugin cache must be created'
    assert h.sh[1].contains('/var/jenkins_home/workspace/circleguard_dev/')

    assert h.sh[2].contains(' fmt -check -recursive -no-color infra/terraform')
    // the isolated data dir is created on the controller, outside the root
    assert h.sh[3].startsWith('mkdir -p'): 'the data dir must be created'
    assert h.sh[3].contains('.terraform-validate/infra/terraform/envs/dev')
    assert h.sh[4].contains(' init -backend=false -no-color')
    assert h.sh[4].contains("-w '/ws/infra/terraform/envs/dev'")
    assert h.sh[4].contains('-e TF_PLUGIN_CACHE_DIR')
    assert h.sh[4].contains('-e TF_DATA_DIR')
    assert h.sh[5].contains(' validate -no-color')
    assert h.sh[5].contains("-w '/ws/infra/terraform/envs/dev'")
    assert h.sh[5].contains('-e TF_DATA_DIR')

    // no terraform command may run before the disk check
    assert !h.sh[0].contains('docker run')

    h.sh.findAll { it.contains('docker run') }.each { String cmd ->
        assert !cmd.contains(' plan '): "plan must never run: ${cmd}"
        assert !cmd.contains(' apply'): "apply must never run: ${cmd}"
        assert !cmd.contains(' destroy'): "destroy must never run: ${cmd}"
        assert !cmd.contains('-upgrade'): "the lockfile must not be upgraded: ${cmd}"
        assert !cmd.contains('-e AWS_'): "no AWS credentials are needed: ${cmd}"
        assert !cmd.contains('-var '): "variables are never injected: ${cmd}"
        // the cache and the data dir are passed by NAME, their value never reaches the command line
        assert !cmd.contains('TF_PLUGIN_CACHE_DIR=/'): "the value must not be in the command: ${cmd}"
        assert !cmd.contains('TF_DATA_DIR=/'): "the value must not be in the command: ${cmd}"
    }
    assert h.sh.count { it.contains('-backend=false') } == 1
}

test('passes TF_PLUGIN_CACHE_DIR and TF_DATA_DIR scoped with withEnv') {
    def h = newStep('terraformValidate')
    h.script.call(roots: ['infra/terraform/envs/dev'], fmtPath: 'infra/terraform')
    // init (cache + data dir) and validate (data dir only), both scoped
    assert h.withEnv.size() == 2: 'both terraform commands must be scoped'
    assert h.withEnv[0].contains('TF_PLUGIN_CACHE_DIR=/ws/.terraform-plugin-cache')
    assert h.withEnv[0].contains('TF_DATA_DIR=/ws/.terraform-validate/infra/terraform/envs/dev')
    assert h.withEnv[1] == ['TF_DATA_DIR=/ws/.terraform-validate/infra/terraform/envs/dev']
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
    // df + mkdir (cache) + fmt + (mkdir (data dir) + init + validate) * 4
    assert h.sh.size() == 15
    assert h.sh.count { it.contains(' fmt -check ') } == 1
    assert h.sh.count { it.contains(' init -backend=false ') } == 4
    assert h.sh.count { it.contains(' validate ') } == 4
    assert h.sh.count { it.startsWith('mkdir -p') } == 5: 'the cache plus one data dir per root'
    assert h.withEnv.size() == 8: 'init and validate of every root must be scoped'
}

test('gives init and validate the same TF_DATA_DIR, and a different one per root') {
    def h = newStep('terraformValidate')
    h.script.call(roots: ['infra/terraform/envs/dev', 'infra/terraform/envs/stage'],
                  fmtPath: 'infra/terraform')

    String dev = '/ws/.terraform-validate/infra/terraform/envs/dev'
    String stage = '/ws/.terraform-validate/infra/terraform/envs/stage'

    // Both commands of a root receive the same value, and two roots never share it.
    List<String> scoped = h.withEnv.flatten().findAll { it.toString().startsWith('TF_DATA_DIR=') }
    assert scoped == ['TF_DATA_DIR=' + dev, 'TF_DATA_DIR=' + dev,
                      'TF_DATA_DIR=' + stage, 'TF_DATA_DIR=' + stage]: "${scoped}"

    String initDev = h.sh.find { it.contains(' init -backend=false ') &&
                                 it.contains("-w '/ws/infra/terraform/envs/dev'") }
    String validateDev = h.sh.find { it.contains(' validate -no-color') &&
                                     it.contains("-w '/ws/infra/terraform/envs/dev'") }
    assert initDev && validateDev: 'both commands of the root must run'
    assert initDev.contains('-e TF_PLUGIN_CACHE_DIR -e TF_DATA_DIR'): initDev
    assert validateDev.contains('-e TF_DATA_DIR'): validateDev
    // The value is passed by NAME only, so it never reaches the command line or the log.
    assert !initDev.contains('TF_DATA_DIR=/'): 'the value must not be in the command'
    assert !validateDev.contains('TF_DATA_DIR=/'): 'the value must not be in the command'
    // The plugin cache stays shared (same value for every root) and only in init.
    assert h.withEnv.flatten().count { it.toString() == 'TF_PLUGIN_CACHE_DIR=/ws/.terraform-plugin-cache' } == 2
    assert !validateDev.contains('-e TF_PLUGIN_CACHE_DIR'): 'validate keeps its previous environment'
    // No AWS credential is ever passed to the validation container.
    assert !initDev.contains('-e AWS_') && !validateDev.contains('-e AWS_')
}

test('never reads nor writes the .terraform left by plan/apply in the root') {
    def h = newStep('terraformValidate')
    h.script.call(roots: ['infra/terraform/envs/dev'], fmtPath: 'infra/terraform')

    h.sh.each { String cmd ->
        assert !cmd.contains('envs/dev/.terraform'): "the .terraform of the root must not be touched: ${cmd}"
        assert !cmd.contains('rm -rf'): "nothing may be deleted: ${cmd}"
    }
    // The data dir is created outside the root, under the workspace.
    String mkdirData = h.sh.find { it.startsWith('mkdir -p') && it.contains('.terraform-validate') }
    assert mkdirData == 'mkdir -p ' +
        '"/var/jenkins_home/workspace/circleguard_dev/.terraform-validate/infra/terraform/envs/dev"'
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
    // the hash is part of the return value (S2) and matches the sidecar
    assert result.sha256 == PLAN_SHA: result
    assert result.containsKey('sha256'): 'the hash must be returned'
    assert result.keySet().containsAll(['root', 'planFile', 'planInfo', 'changes', 'status']):
        "the previous fields must be kept: ${result.keySet()}"
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

test('refuses to produce a plan whose provenance commit is unavailable') {
    // GIT_COMMIT is the only source of the commit recorded in the sidecar: when
    // it is missing the step must stop BEFORE any command, leaving no sidecar and
    // binding no credential (the old `commit=unknown` fallback is gone).
    def h = newStep('terraformPlan', [env: [WORKSPACE   : '/var/jenkins_home/workspace/circleguard_dev',
                                            BUILD_NUMBER: '42']])
    try {
        h.script.call(root: 'infra/terraform/envs/dev')
        assert false: 'a plan without GIT_COMMIT must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('GIT_COMMIT is not available'): e.message
        assert e.message.contains('provenance'): e.message
    }
    assert h.sh.isEmpty(): 'nothing must run before the provenance is available'
    assert h.written.isEmpty(): 'no sidecar without a recordable commit'
    assert h.withCredentials.isEmpty(): 'no credential must be bound'
}

test('records the real commit in the sidecar and never falls back to unknown (source level)') {
    String step = new File(root, 'vars/terraformPlan.groovy').text
    assert step.contains('if (!env.GIT_COMMIT)'): 'the provenance must be validated'
    assert step.contains('GIT_COMMIT is not available'): 'the failure must be explicit'
    assert !step.contains("?: 'unknown'"): 'the fallback must be removed'
    assert step.contains('commit=${env.GIT_COMMIT}'): 'the sidecar must record the real commit'
    // the guard runs before the sidecar exists, so no plan can end successfully
    // without a verifiable provenance
    assert step.indexOf('GIT_COMMIT is not available') < step.indexOf('writeFile file: infoPath'):
        'the provenance must be checked before the sidecar is written'
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

println 'terraformApproval'
// Local stand-ins for the Jenkins exception and its timeout cause: the real
// classes are not on the classpath of the tests and the step detects them BY
// NAME (importing them would make these tests impossible to run locally).
class FlowInterruptedException extends RuntimeException {
    List causes = []
    FlowInterruptedException(String message) { super(message) }
    FlowInterruptedException(String message, List causes) { super(message); this.causes = causes }
}
class ExceededTimeout { }

String APPR_ROOT = 'infra/terraform/envs/dev'
String APPR_PLAN_PATH = "${APPR_ROOT}/ci-dev-b42.tfplan"
String APPR_INFO_PATH = "${APPR_PLAN_PATH}.info"
String APPR_SHA = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'

// sidecar of a plan produced 5 minutes ago (inside the 60 minute limit)
def approvalSidecar = { String createdAt = java.time.Instant.now().minusSeconds(300).toString() ->
    "build=42\ncommit=abc1234\nroot=${APPR_ROOT}\nchanges=true\nstatus=2\n" +
    "sha256=${APPR_SHA}\ncreatedAt=${createdAt}\n"
}

def approvalEnv = { Map extra = [:] ->
    Map e = [WORKSPACE: '/var/jenkins_home/workspace/circleguard_dev',
             BUILD_NUMBER: '42', GIT_COMMIT: 'abc1234', BRANCH_NAME: 'dev',
             TF_PLAN_BUILD: '42', TF_PLAN_ROOT: APPR_ROOT,
             TF_PLAN_FILE: APPR_PLAN_PATH, TF_PLAN_INFO: APPR_INFO_PATH,
             TF_PLAN_SHA256: APPR_SHA, TF_PLAN_CHANGES: 'true']
    e.putAll(extra)
    e
}

test('asks for the approval and persists the four values') {
    def h = newStep('terraformApproval', [env: approvalEnv(),
                                          files: [(APPR_INFO_PATH): approvalSidecar()],
                                          stdout: APPR_SHA,
                                          inputResult: 'alice'])
    def result = h.script.call(root: APPR_ROOT, submitter: 'admin',
                               timeout: 30, maxAgeMinutes: 60)

    // the only command is the local hash: no docker, no terraform, no AWS
    assert h.sh.size() == 1: "expected only sha256sum, got ${h.sh}"
    assert h.sh[0] == "sha256sum \"${APPR_PLAN_PATH}\"": h.sh[0]
    assert !h.sh.any { it.contains('docker run') }: 'no container may be started'

    // the input carries the required identity and limits
    assert h.inputs.size() == 1: 'input must be called exactly once'
    Map inp = h.inputs[0]
    assert inp.submitter == 'admin': inp
    assert inp.submitterParameter == 'approvedBy': inp
    assert inp.timeout == 30: inp
    assert inp.timeUnit == 'MINUTES': inp
    assert inp.ok == 'Approve terraform apply': inp
    // and the message identifies the plan being approved
    assert inp.message.contains('Build     : 42'): inp.message
    assert inp.message.contains('Commit    : abc1234'): inp.message
    assert inp.message.contains("Root      : ${APPR_ROOT}"): inp.message
    assert inp.message.contains("SHA-256   : ${APPR_SHA}"): inp.message
    assert inp.message.contains('Changes   : yes'): inp.message
    assert inp.message.contains('Plan age  :'): inp.message

    // the four values are persisted
    assert h.env.TF_APPROVED_BY == 'alice': h.env
    assert h.env.TF_APPROVED_AT && h.env.TF_APPROVED_AT.length() > 10: h.env
    assert h.env.TF_APPROVED_PLAN_SHA == APPR_SHA: h.env
    assert h.env.TF_APPROVED_BUILD == '42': h.env

    assert result.approvedBy == 'alice'
    assert result.approvedAt == h.env.TF_APPROVED_AT
    assert result.sha256 == APPR_SHA
    assert result.build == '42'
}

test('rejects a plan of another build, commit, root or hash before asking') {
    // build of another build (env)
    def a = newStep('terraformApproval', [env: approvalEnv([TF_PLAN_BUILD: '41']),
                                          files: [(APPR_INFO_PATH): approvalSidecar()],
                                          stdout: APPR_SHA])
    try {
        a.script.call(root: APPR_ROOT)
        assert false: 'a plan of another build must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('belongs to build 41'): e.message
    }

    // commit of another revision (sidecar)
    String otherCommit = approvalSidecar().replace('commit=abc1234', 'commit=deadbee')
    def b = newStep('terraformApproval', [env: approvalEnv(),
                                          files: [(APPR_INFO_PATH): otherCommit],
                                          stdout: APPR_SHA])
    try {
        b.script.call(root: APPR_ROOT)
        assert false: 'a plan of another commit must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('another revision'): e.message
    }

    // root of another environment (env)
    def c = newStep('terraformApproval', [env: approvalEnv([TF_PLAN_ROOT: 'infra/terraform/envs/stage']),
                                          files: [(APPR_INFO_PATH): approvalSidecar()],
                                          stdout: APPR_SHA])
    try {
        c.script.call(root: APPR_ROOT)
        assert false: 'a plan of another root must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('refusing to approve the wrong plan'): e.message
    }

    // root of another environment (sidecar)
    String otherRoot = approvalSidecar().replace("root=${APPR_ROOT}", 'root=infra/terraform/envs/stage')
    def d = newStep('terraformApproval', [env: approvalEnv(),
                                          files: [(APPR_INFO_PATH): otherRoot],
                                          stdout: APPR_SHA])
    try {
        d.script.call(root: APPR_ROOT)
        assert false: 'a sidecar of another root must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('the sidecar says root=infra/terraform/envs/stage'): e.message
    }

    // hash published by the plan stage differs from the sidecar
    def e1 = newStep('terraformApproval', [env: approvalEnv([TF_PLAN_SHA256: PLAN_SHA]),
                                           files: [(APPR_INFO_PATH): approvalSidecar()],
                                           stdout: APPR_SHA])
    try {
        e1.script.call(root: APPR_ROOT)
        assert false: 'an inconsistent hash must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('inconsistent plan state'): e.message
    }

    // every one of them fails before the hash command and before the input
    [a, b, c, d, e1].eachWithIndex { def h, int i ->
        assert h.sh.isEmpty(): "case ${i}: nothing must run (${h.sh})"
        assert h.inputs.isEmpty(): "case ${i}: input must not be called"
        assert !h.env.containsKey('TF_APPROVED_BY'): "case ${i}: no approval may be persisted"
    }
}

test('refuses a plan whose recomputed sha256 differs from the sidecar') {
    def h = newStep('terraformApproval', [env: approvalEnv(),
                                          files: [(APPR_INFO_PATH): approvalSidecar()],
                                          stdout: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'])
    try {
        h.script.call(root: APPR_ROOT)
        assert false: 'a modified plan must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('the plan changed after it was produced'): e.message
        assert e.message.contains(APPR_SHA): e.message
    }
    assert h.sh.size() == 1: 'the hash was computed'
    assert h.sh[0].startsWith('sha256sum')
    assert h.inputs.isEmpty(): 'input must not be called'
    assert !h.env.containsKey('TF_APPROVED_BY')
}

test('rejects a missing or malformed sidecar') {
    def missing = newStep('terraformApproval', [env: approvalEnv(),
                                                missing: [APPR_INFO_PATH]])
    try {
        missing.script.call(root: APPR_ROOT)
        assert false: 'a missing sidecar must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('sidecar'): e.message
    }

    def malformed = newStep('terraformApproval', [env: approvalEnv(),
                                                  files: [(APPR_INFO_PATH): 'garbage\nwithout keys\n']])
    try {
        malformed.script.call(root: APPR_ROOT)
        assert false: 'a malformed sidecar must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('the sidecar says build=null'): e.message
    }

    [missing, malformed].each { def h ->
        assert h.sh.isEmpty(): "nothing must run (${h.sh})"
        assert h.inputs.isEmpty(): 'input must not be called'
        assert !h.env.containsKey('TF_APPROVED_BY')
    }
}

test('refuses a plan without changes') {
    def noChanges = newStep('terraformApproval', [env: approvalEnv([TF_PLAN_CHANGES: 'false']),
                                                  files: [(APPR_INFO_PATH): approvalSidecar()],
                                                  stdout: APPR_SHA])
    try {
        noChanges.script.call(root: APPR_ROOT)
        assert false: 'a plan without changes must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('nothing to approve'): e.message
    }

    String sidecarNoChanges = approvalSidecar().replace('changes=true', 'changes=false')
    def sidecarSays = newStep('terraformApproval', [env: approvalEnv(),
                                                    files: [(APPR_INFO_PATH): sidecarNoChanges],
                                                    stdout: APPR_SHA])
    try {
        sidecarSays.script.call(root: APPR_ROOT)
        assert false: 'a sidecar without changes must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('the sidecar says changes=false'): e.message
    }

    [noChanges, sidecarSays].each { def h ->
        assert h.sh.isEmpty(): "nothing must run (${h.sh})"
        assert h.inputs.isEmpty(): 'input must not be called'
        assert !h.env.containsKey('TF_APPROVED_BY')
    }
}

test('refuses a plan older than the maximum age') {
    String old = java.time.Instant.now().minusSeconds(120 * 60).toString()
    def h = newStep('terraformApproval', [env: approvalEnv(),
                                          files: [(APPR_INFO_PATH): approvalSidecar(old)],
                                          stdout: APPR_SHA])
    try {
        h.script.call(root: APPR_ROOT, maxAgeMinutes: 60)
        assert false: 'an expired plan must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('more than the maximum of 60'): e.message
        assert e.message.contains('request a new build'): e.message
    }
    assert h.sh.size() == 1: 'the hash was computed before the age check'
    assert h.inputs.isEmpty(): 'input must not be called'
    assert !h.env.containsKey('TF_APPROVED_BY')
}

test('refuses an invalid or future createdAt') {
    def invalid = newStep('terraformApproval', [env: approvalEnv(),
                                                files: [(APPR_INFO_PATH): approvalSidecar('not-a-date')],
                                                stdout: APPR_SHA])
    try {
        invalid.script.call(root: APPR_ROOT)
        assert false: 'an invalid timestamp must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('invalid createdAt'): e.message
    }

    String future = java.time.Instant.now().plusSeconds(5 * 60).toString()
    def futurePlan = newStep('terraformApproval', [env: approvalEnv(),
                                                   files: [(APPR_INFO_PATH): approvalSidecar(future)],
                                                   stdout: APPR_SHA])
    try {
        futurePlan.script.call(root: APPR_ROOT)
        assert false: 'a future timestamp must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('dated in the future'): e.message
    }

    [invalid, futurePlan].each { def h ->
        assert h.sh.size() == 1: 'the hash was computed'
        assert h.inputs.isEmpty(): 'input must not be called'
        assert !h.env.containsKey('TF_APPROVED_BY')
    }
}

test('rethrows the original interruption without persisting any approval') {
    // expired (timeout)
    def expired = new FlowInterruptedException('Timeout has been exceeded')
    def h1 = newStep('terraformApproval', [env: approvalEnv(),
                                           files: [(APPR_INFO_PATH): approvalSidecar()],
                                           stdout: APPR_SHA,
                                           failInput: expired])
    try {
        h1.script.call(root: APPR_ROOT)
        assert false: 'an expired approval must fail the step'
    } catch (RuntimeException e) {
        assert e.is(expired): 'the ORIGINAL exception must be rethrown'
        assert e.message.contains('Timeout has been exceeded'): e.message
    }
    assert h1.inputs.size() == 1: 'input was attempted'
    assert h1.logs.any { it.contains('NO infrastructure was changed') }: h1.logs
    assert h1.logs.any { it.contains('expired or cancelled') }: h1.logs
    assert !h1.env.containsKey('TF_APPROVED_BY'): 'no approval may be persisted'
    assert !h1.env.containsKey('TF_APPROVED_PLAN_SHA')

    // cancelled by the user (cause reported by Jenkins)
    def cancelled = new FlowInterruptedException('Aborted by user', [new Object()])
    def h2 = newStep('terraformApproval', [env: approvalEnv(),
                                           files: [(APPR_INFO_PATH): approvalSidecar()],
                                           stdout: APPR_SHA,
                                           failInput: cancelled])
    try {
        h2.script.call(root: APPR_ROOT)
        assert false: 'a cancelled approval must fail the step'
    } catch (RuntimeException e) {
        assert e.is(cancelled): 'the ORIGINAL exception must be rethrown'
    }
    assert h2.logs.any { it.contains('was cancelled') }: h2.logs
    assert !h2.env.containsKey('TF_APPROVED_BY')

    // timeout cause reported by Jenkins
    def timedOut = new FlowInterruptedException('Timeout', [new ExceededTimeout()])
    def h3 = newStep('terraformApproval', [env: approvalEnv(),
                                           files: [(APPR_INFO_PATH): approvalSidecar()],
                                           stdout: APPR_SHA,
                                           failInput: timedOut])
    try {
        h3.script.call(root: APPR_ROOT)
        assert false: 'a timed out approval must fail the step'
    } catch (RuntimeException e) {
        assert e.is(timedOut): 'the ORIGINAL exception must be rethrown'
    }
    assert h3.logs.any { it.contains('expired (timeout)') }: h3.logs
    assert !h3.env.containsKey('TF_APPROVED_BY')
}

test('refuses an approval without a valid identity') {
    def empty = newStep('terraformApproval', [env: approvalEnv(),
                                              files: [(APPR_INFO_PATH): approvalSidecar()],
                                              stdout: APPR_SHA,
                                              inputResult: ''])
    try {
        empty.script.call(root: APPR_ROOT)
        assert false: 'an empty identity must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('no valid identity'): e.message
    }
    assert empty.inputs.size() == 1: 'input was attempted'
    assert !empty.env.containsKey('TF_APPROVED_BY'): 'no approval may be persisted'
    assert !empty.env.containsKey('TF_APPROVED_AT')
    assert !empty.env.containsKey('TF_APPROVED_PLAN_SHA')
    assert !empty.env.containsKey('TF_APPROVED_BUILD')

    def nullIdentity = newStep('terraformApproval', [env: approvalEnv(),
                                                     files: [(APPR_INFO_PATH): approvalSidecar()],
                                                     stdout: APPR_SHA,
                                                     inputResult: null])
    try {
        nullIdentity.script.call(root: APPR_ROOT)
        assert false: 'a missing identity must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('no valid identity'): e.message
    }
    assert nullIdentity.inputs.size() == 1
    assert !nullIdentity.env.containsKey('TF_APPROVED_BY')
}

test('never runs Docker, Terraform or AWS commands (source level)') {
    String step = new File(root, 'vars/terraformApproval.groovy').text
    assert !step.contains('docker run'): 'no container'
    assert !step.contains('runInContainer'): 'this step never starts a container'
    assert !step.contains('withCredentials'): 'no AWS credential in this step'
    assert !step.contains('AWS_ACCESS_KEY_ID'): 'no AWS variable'
    assert !step.contains('sh "terraform'): 'no terraform command'
    assert step.contains('sha256sum'): 'the local hash is required'
    assert step.contains('submitterParameter'): 'the approver must be recorded'
    assert step.contains('throw e'): 'the original interruption must be rethrown'
    assert step.contains('TF_APPROVED_PLAN_SHA')
    // S5: the pipeline invokes it from its own stage, between plan and apply
    String pipeline = new File(root, 'vars/circleguardPipeline.groovy').text
    assert pipeline.contains("stage('Terraform approval')"): 'the approval stage must exist'
    assert pipeline.contains('terraformApproval('): 'the pipeline must invoke the step'
}

// --- approval gate (S4): only a target with requireApproval goes through this ---
// sidecar with a createdAt inside the validity window (5 minutes old)
def freshSidecar = { String createdAt = java.time.Instant.now().minusSeconds(300).toString() ->
    APPLY_SIDECAR.replaceFirst('createdAt=[^\n]*', "createdAt=${createdAt}")
}

// env of a build whose plan was approved for THIS build and THIS hash
def approvedEnv = { Map extra = [:] ->
    Map e = applyEnv('true', [TF_PLAN_SHA256: APPLY_SHA,
                              TF_APPROVED_BY: 'alice',
                              TF_APPROVED_AT: java.time.Instant.now().minusSeconds(120).toString(),
                              TF_APPROVED_PLAN_SHA: APPLY_SHA,
                              TF_APPROVED_BUILD: '42'])
    e.putAll(extra)
    e
}

test('applies DEV without any approval when the target does not require one') {
    def h = newStep('terraformApply', [env: applyEnv('true'),   // no TF_APPROVED_* at all
                                       files: [(APPLY_INFO_PATH): APPLY_SIDECAR],
                                       missing: [APPLY_MARKER],
                                       stdout: APPLY_SHA])
    def result = h.script.call(root: APPLY_ROOT) // requireApproval defaults to false

    assert result.status == 'APPLIED': result
    // the exact command sequence of the approved DEV behaviour
    assert h.sh.size() == 6: "expected 6 commands, got ${h.sh.size()}"
    assert h.sh[0].startsWith('df -Pk')
    assert h.sh[1].startsWith('sha256sum')
    assert h.sh[4].contains(' apply ')
    assert h.sh[5].startsWith('rm -f')
    assert h.withCredentials.size() == 1
    assert !h.env.containsKey('TF_APPROVED_BY'): 'DEV must not demand an approval'
    assert h.archived == [APPLY_EVIDENCE]
    assert !h.written[APPLY_EVIDENCE].contains('Approved by'):
        'DEV evidence must not carry approval fields'
}

test('refuses an approval-gated apply when any approval value is missing') {
    ['TF_APPROVED_BY', 'TF_APPROVED_AT', 'TF_APPROVED_PLAN_SHA', 'TF_APPROVED_BUILD'].each { String key ->
        Map env = approvedEnv()
        env.remove(key)
        def h = newStep('terraformApply', [env: env,
                                           files: [(APPLY_INFO_PATH): freshSidecar()],
                                           missing: [APPLY_MARKER],
                                           stdout: APPLY_SHA])
        try {
            h.script.call(root: APPLY_ROOT, requireApproval: true)
            assert false: "a missing ${key} must be rejected"
        } catch (RuntimeException e) {
            assert e.message.contains(key): e.message
        }
        assert h.withCredentials.isEmpty(): "${key}: must fail before the credentials"
        assert !h.sh.any { it.contains('docker run') }: "${key}: must fail before Terraform"
    }
}

test('refuses an approval issued for another build or with an empty approver') {
    def otherBuild = newStep('terraformApply', [env: approvedEnv([TF_APPROVED_BUILD: '41']),
                                                files: [(APPLY_INFO_PATH): freshSidecar()],
                                                missing: [APPLY_MARKER],
                                                stdout: APPLY_SHA])
    try {
        otherBuild.script.call(root: APPLY_ROOT, requireApproval: true)
        assert false: 'an approval of another build must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('the approval belongs to build 41'): e.message
    }

    def emptyApprover = newStep('terraformApply', [env: approvedEnv([TF_APPROVED_BY: '']),
                                                   files: [(APPLY_INFO_PATH): freshSidecar()],
                                                   missing: [APPLY_MARKER],
                                                   stdout: APPLY_SHA])
    try {
        emptyApprover.script.call(root: APPLY_ROOT, requireApproval: true)
        assert false: 'an empty approver must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('no valid identity'): e.message
    }

    [otherBuild, emptyApprover].each { def h ->
        assert h.withCredentials.isEmpty(): 'must fail before the credentials'
        assert !h.sh.any { it.contains('docker run') }: 'must fail before Terraform'
    }
}

test('refuses an approval whose SHA does not match the plan') {
    // approved for another hash
    def approvedFor = newStep('terraformApply', [env: approvedEnv([TF_APPROVED_PLAN_SHA: PLAN_SHA]),
                                                 files: [(APPLY_INFO_PATH): freshSidecar()],
                                                 missing: [APPLY_MARKER],
                                                 stdout: APPLY_SHA])
    try {
        approvedFor.script.call(root: APPLY_ROOT, requireApproval: true)
        assert false: 'an approval for another hash must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('the approval is for sha256'): e.message
    }

    // sidecar hash different from the hash published by the plan stage
    def sidecarDiffers = newStep('terraformApply', [
        env: approvedEnv([TF_PLAN_SHA256: PLAN_SHA, TF_APPROVED_PLAN_SHA: PLAN_SHA]),
        files: [(APPLY_INFO_PATH): freshSidecar()],
        missing: [APPLY_MARKER],
        stdout: APPLY_SHA])
    try {
        sidecarDiffers.script.call(root: APPLY_ROOT, requireApproval: true)
        assert false: 'a sidecar hash mismatch must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('the sidecar says sha256='): e.message
    }

    // the file on disk was modified after the approval
    def tampered = newStep('terraformApply', [env: approvedEnv(),
                                              files: [(APPLY_INFO_PATH): freshSidecar()],
                                              missing: [APPLY_MARKER],
                                              stdout: PLAN_SHA])
    try {
        tampered.script.call(root: APPLY_ROOT, requireApproval: true)
        assert false: 'a modified plan file must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('the plan changed after it was produced'): e.message
    }

    [approvedFor, sidecarDiffers, tampered].each { def h ->
        assert h.withCredentials.isEmpty(): 'must fail before the credentials'
        assert !h.sh.any { it.contains('docker run') }: 'must fail before Terraform'
    }
}

test('refuses an approval for a sidecar of another commit or root') {
    def otherCommit = newStep('terraformApply', [env: approvedEnv(),
                                                 files: [(APPLY_INFO_PATH): freshSidecar()
                                                     .replace('commit=abc1234', 'commit=deadbee')],
                                                 missing: [APPLY_MARKER],
                                                 stdout: APPLY_SHA])
    try {
        otherCommit.script.call(root: APPLY_ROOT, requireApproval: true)
        assert false: 'a sidecar of another commit must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('another revision'): e.message
    }

    def otherRoot = newStep('terraformApply', [env: approvedEnv(),
                                               files: [(APPLY_INFO_PATH): freshSidecar()
                                                   .replace("root=${APPLY_ROOT}", 'root=infra/terraform/envs/stage')],
                                               missing: [APPLY_MARKER],
                                               stdout: APPLY_SHA])
    try {
        otherRoot.script.call(root: APPLY_ROOT, requireApproval: true)
        assert false: 'a sidecar of another root must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('the sidecar says root='): e.message
    }

    [otherCommit, otherRoot].each { def h ->
        assert h.withCredentials.isEmpty(): 'must fail before the credentials'
        assert !h.sh.any { it.contains('docker run') }: 'must fail before Terraform'
    }
}

test('refuses an expired plan or an approval outside the window') {
    // expired plan: the approval is NEWER, so what fails is the age of the plan
    String oldPlan = java.time.Instant.now().minusSeconds(120 * 60).toString()
    def expiredPlan = newStep('terraformApply', [env: approvedEnv(),
                                                 files: [(APPLY_INFO_PATH): freshSidecar(oldPlan)],
                                                 missing: [APPLY_MARKER],
                                                 stdout: APPLY_SHA])
    try {
        expiredPlan.script.call(root: APPLY_ROOT, requireApproval: true, maxAgeMinutes: 60)
        assert false: 'an expired plan must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('the plan is'): e.message
        assert e.message.contains('more than the maximum of 60'): e.message
        assert e.message.contains('request a new build'): e.message
    }

    // An approval older than the window is necessarily OLDER than a fresh plan
    // (an approval is always produced after the plan), so it is caught by the
    // temporal rule. The dedicated age branch of checkApproval stays as defence
    // in depth: it is only reachable if `createdAt` were tampered with.
    def oldApproval = newStep('terraformApply', [
        env: approvedEnv([TF_APPROVED_AT: java.time.Instant.now().minusSeconds(120 * 60).toString()]),
        files: [(APPLY_INFO_PATH): freshSidecar()],
        missing: [APPLY_MARKER],
        stdout: APPLY_SHA])
    try {
        oldApproval.script.call(root: APPLY_ROOT, requireApproval: true, maxAgeMinutes: 60)
        assert false: 'an approval outside the window must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('older than the plan'): e.message
        assert e.message.contains('does not correspond to this plan'): e.message
    }

    [expiredPlan, oldApproval].each { def h ->
        assert h.withCredentials.isEmpty(): 'must fail before the credentials'
        assert !h.sh.any { it.contains('docker run') }: 'must fail before Terraform'
    }
}

test('refuses an invalid or future approval date or plan date') {
    def badApprovalDate = newStep('terraformApply', [env: approvedEnv([TF_APPROVED_AT: 'not-a-date']),
                                                     files: [(APPLY_INFO_PATH): freshSidecar()],
                                                     missing: [APPLY_MARKER],
                                                     stdout: APPLY_SHA])
    try {
        badApprovalDate.script.call(root: APPLY_ROOT, requireApproval: true)
        assert false: 'an invalid approval date must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('invalid TF_APPROVED_AT'): e.message
    }

    def futureApproval = newStep('terraformApply', [
        env: approvedEnv([TF_APPROVED_AT: java.time.Instant.now().plusSeconds(300).toString()]),
        files: [(APPLY_INFO_PATH): freshSidecar()],
        missing: [APPLY_MARKER],
        stdout: APPLY_SHA])
    try {
        futureApproval.script.call(root: APPLY_ROOT, requireApproval: true)
        assert false: 'a future approval date must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('approval is dated in the future'): e.message
    }

    def badPlanDate = newStep('terraformApply', [env: approvedEnv(),
                                                 files: [(APPLY_INFO_PATH): freshSidecar('not-a-date')],
                                                 missing: [APPLY_MARKER],
                                                 stdout: APPLY_SHA])
    try {
        badPlanDate.script.call(root: APPLY_ROOT, requireApproval: true)
        assert false: 'an invalid plan date must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('invalid createdAt'): e.message
    }

    def futurePlan = newStep('terraformApply', [env: approvedEnv(),
                                                files: [(APPLY_INFO_PATH): freshSidecar(
                                                    java.time.Instant.now().plusSeconds(300).toString())],
                                                missing: [APPLY_MARKER],
                                                stdout: APPLY_SHA])
    try {
        futurePlan.script.call(root: APPLY_ROOT, requireApproval: true)
        assert false: 'a future plan date must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('plan is dated in the future'): e.message
    }

    [badApprovalDate, futureApproval, badPlanDate, futurePlan].each { def h ->
        assert h.withCredentials.isEmpty(): 'must fail before the credentials'
        assert !h.sh.any { it.contains('docker run') }: 'must fail before Terraform'
    }
}

test('refuses an approval when the plan has no changes') {
    Map env = applyEnv('false', [TF_PLAN_SHA256: APPLY_SHA,
                                 TF_APPROVED_BY: 'alice',
                                 TF_APPROVED_AT: java.time.Instant.now().minusSeconds(60).toString(),
                                 TF_APPROVED_PLAN_SHA: APPLY_SHA,
                                 TF_APPROVED_BUILD: '42'])
    String sidecar = freshSidecar().replace('changes=true', 'changes=false')
                                   .replace('status=2', 'status=0')
    def h = newStep('terraformApply', [env: env,
                                       files: [(APPLY_INFO_PATH): sidecar],
                                       missing: [APPLY_MARKER],
                                       stdout: APPLY_SHA])
    try {
        h.script.call(root: APPLY_ROOT, requireApproval: true)
        assert false: 'a plan without changes must be rejected for an approval-gated target'
    } catch (RuntimeException e) {
        assert e.message.contains('there is nothing to approve'): e.message
    }
    assert h.sh.isEmpty(): 'the gate runs before any command (no df, no hash)'
    assert h.withCredentials.isEmpty(): 'must fail before the credentials'
    assert !h.sh.any { it.contains('docker run') }
}

test('applies with a valid approval and records it in the evidence') {
    def h = newStep('terraformApply', [env: approvedEnv(),
                                       files: [(APPLY_INFO_PATH): freshSidecar()],
                                       missing: [APPLY_MARKER],
                                       stdout: APPLY_SHA])
    def result = h.script.call(root: APPLY_ROOT, requireApproval: true, maxAgeMinutes: 60)

    assert result.status == 'APPLIED': result
    assert h.sh.size() == 6: "expected 6 commands, got ${h.sh.size()}"
    assert h.sh[4].contains(' apply ')
    assert h.withCredentials.size() == 1: 'the credential is bound only after the approval'
    assert h.logs.any { it.contains('approval verified (by alice') }: h.logs

    // the evidence carries everything the approval must be traceable by
    String ev = h.written[APPLY_EVIDENCE]
    assert ev != null: 'the evidence must be written'
    assert ev.contains('Approved by : alice'): ev
    assert ev.contains('Approved at : '): ev
    assert ev.contains("Approved sha: ${APPLY_SHA}"): ev
    assert ev.contains('Approved bld: 42'): ev
    assert ev.contains('Plan age    : '): ev
    assert ev.contains('min at apply'): ev
    // and nothing sensitive
    assert !ev.contains('AWS_SECRET'): ev
    assert !ev.contains('SecretAccessKey'): ev
    assert h.archived == [APPLY_EVIDENCE]
}

test('refuses an approval issued before the plan was created') {
    String createdAt = java.time.Instant.now().minusSeconds(5 * 60).toString()
    String approvedAt = java.time.Instant.now().minusSeconds(30 * 60).toString() // older
    def h = newStep('terraformApply', [env: approvedEnv([TF_APPROVED_AT: approvedAt]),
                                       files: [(APPLY_INFO_PATH): freshSidecar(createdAt)],
                                       missing: [APPLY_MARKER],
                                       stdout: APPLY_SHA])
    try {
        h.script.call(root: APPLY_ROOT, requireApproval: true)
        assert false: 'an approval older than the plan must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('older than the plan'): e.message
        assert e.message.contains('does not correspond to this plan'): e.message
        assert e.message.contains(createdAt): 'the message must show the plan date'
        assert e.message.contains(approvedAt): 'the message must show the approval date'
    }
    assert h.withCredentials.isEmpty(): 'must fail before the credentials'
    assert !h.sh.any { it.contains('docker run') }: 'must fail before Terraform'
}

test('accepts an approval dated exactly when the plan was created') {
    String stamp = java.time.Instant.now().minusSeconds(5 * 60).toString()
    def h = newStep('terraformApply', [env: approvedEnv([TF_APPROVED_AT: stamp]),
                                       files: [(APPLY_INFO_PATH): freshSidecar(stamp)],
                                       missing: [APPLY_MARKER],
                                       stdout: APPLY_SHA])
    def result = h.script.call(root: APPLY_ROOT, requireApproval: true, maxAgeMinutes: 60)

    assert result.status == 'APPLIED': result
    assert h.sh.size() == 6: "expected 6 commands, got ${h.sh.size()}"
    assert h.sh[4].contains(' apply ')
    assert h.withCredentials.size() == 1: 'the credential is bound after the approval'
    String ev = h.written[APPLY_EVIDENCE]
    assert ev.contains("Approved at : ${stamp}"): ev
    assert ev.contains('Approved by : alice'): ev
    assert ev.contains('Plan age    : 5 min at apply'): ev
    assert h.archived == [APPLY_EVIDENCE]
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

    // The container keeps the agent uid/gid (asserted above) and receives the
    // group that OWNS the socket as a supplementary group. The GID is resolved
    // at run time with `stat` (never a fixed value): without it the daemon
    // answers "permission denied while trying to connect to the docker API".
    assert cmd.contains("--group-add \$(stat -c '%g' /var/run/docker.sock)"):
        'the GID of the socket must be resolved at run time'

    // pinned tool image, blocking threshold, local-only resolution, shared cache.
    // `trivy image` has no --pull flag (0.76.2 fails with "unknown flag: --pull"):
    // the local daemon is selected with --image-src docker instead.
    assert cmd.contains('aquasec/trivy:0.76.2 image --severity HIGH,CRITICAL ' +
                        '--exit-code 1 --image-src docker')
    assert !cmd.contains('--pull'): 'the unsupported --pull flag must be gone'
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

// PipelineConfig constructor wrapper: reflection wraps the IllegalArgumentException
// thrown by the validation, so the tests must unwrap the cause to assert on it.
def newConfig = { Map m ->
    def cls = loader.parseClass(new File(root, 'src/org/circleguard/ci/PipelineConfig.groovy'))
    try {
        return cls.getConstructor(Map).newInstance(m)
    } catch (Throwable t) {
        throw (t instanceof java.lang.reflect.InvocationTargetException && t.cause != null)
                ? t.cause : t
    }
}

test('accepts the Kubernetes kubeconfig and token credential ids from the Jenkinsfile') {
    def cfg = newConfig([deploy: true, environment: 'dev',
                         k8sContexts: [dev: 'cg-dev'],
                         k8sIngressUrls: [dev: 'http://ingress.example'],
                         kubeconfigCredentialId: 'custom-kubeconfig',
                         k8sTokenCredentialId: 'custom-k8s-token'])

    assert cfg.kubeconfigCredentialId == 'custom-kubeconfig'
    assert cfg.k8sTokenCredentialId == 'custom-k8s-token'

    def defaults = newConfig([:])
    assert defaults.kubeconfigCredentialId == null
    assert defaults.k8sTokenCredentialId == null
}

test('keeps the Terraform approval and the PROD target disabled by default') {
    def cfg = newConfig([:])

    // approval feature: off, with safe values
    assert cfg.terraformApproval == false: 'the approval must be off by default'
    assert cfg.terraformApprovalTimeout == 30: cfg.terraformApprovalTimeout
    assert cfg.terraformApprovalSubmitter == 'admin': cfg.terraformApprovalSubmitter
    assert cfg.terraformApprovalMaxAgeMinutes == 60: cfg.terraformApprovalMaxAgeMinutes

    // PROD target is declared but inert: apply AND approval are separate
    // switches and BOTH are off, so it cannot activate by accident.
    assert cfg.terraformApplyProdRoot == 'infra/terraform/envs/prod': cfg.terraformApplyProdRoot
    assert cfg.terraformApplyProdBranches == ['main']: cfg.terraformApplyProdBranches
    assert cfg.terraformApplyProd == false: 'PROD apply must be off by default'
    assert cfg.terraformApprovalProd == false: 'PROD approval must be off by default'

    // the DEV scope of the previous phase is unchanged
    assert cfg.terraformApply == false
    assert cfg.terraformApplyRoot == 'infra/terraform/envs/dev'
    assert cfg.terraformApplyBranches == ['dev']
    assert cfg.terraformPlan == false
}

test('accepts an explicit Terraform approval configuration from the Jenkinsfile') {
    def cfg = newConfig([terraformApproval: true,
                         terraformApprovalTimeout: 45,
                         terraformApprovalSubmitter: 'sre,platform',
                         terraformApprovalMaxAgeMinutes: 15,
                         terraformApplyProd: true,
                         terraformApprovalProd: true,
                         terraformApplyProdRoot: 'infra/terraform/envs/prod',
                         terraformApplyProdBranches: ['main']])

    assert cfg.terraformApproval == true
    assert cfg.terraformApprovalTimeout == 45
    assert cfg.terraformApprovalSubmitter == 'sre,platform'
    assert cfg.terraformApprovalMaxAgeMinutes == 15
    assert cfg.terraformApplyProd == true
    assert cfg.terraformApprovalProd == true
    assert cfg.terraformApplyProdRoot == 'infra/terraform/envs/prod'
    assert cfg.terraformApplyProdBranches == ['main']

    // untouched defaults keep their value
    assert cfg.terraformApply == false
    assert cfg.terraformApplyRoot == 'infra/terraform/envs/dev'
    assert cfg.terraformApplyBranches == ['dev']
    assert cfg.terraformPlan == false
    assert cfg.terraformApplyTimeout == 30
}

test('rejects an invalid Terraform approval configuration') {
    // timeout 0: must NOT be swallowed by the default (0 is falsy in Groovy)
    try {
        newConfig([terraformApprovalTimeout: 0])
        assert false: 'a timeout of 0 must be rejected'
    } catch (IllegalArgumentException e) {
        assert e.message.contains('terraformApprovalTimeout must be > 0'): e.message
    }

    try {
        newConfig([terraformApprovalTimeout: -5])
        assert false: 'a negative timeout must be rejected'
    } catch (IllegalArgumentException e) {
        assert e.message.contains('terraformApprovalTimeout must be > 0'): e.message
    }

    try {
        newConfig([terraformApprovalMaxAgeMinutes: 0])
        assert false: 'a max age of 0 must be rejected'
    } catch (IllegalArgumentException e) {
        assert e.message.contains('terraformApprovalMaxAgeMinutes must be > 0'): e.message
    }

    try {
        newConfig([terraformApprovalMaxAgeMinutes: -1])
        assert false: 'a negative max age must be rejected'
    } catch (IllegalArgumentException e) {
        assert e.message.contains('terraformApprovalMaxAgeMinutes must be > 0'): e.message
    }

    try {
        newConfig([terraformApprovalSubmitter: ''])
        assert false: 'an empty submitter must be rejected'
    } catch (IllegalArgumentException e) {
        assert e.message.contains('terraformApprovalSubmitter must not be empty'): e.message
    }

    try {
        newConfig([terraformApprovalSubmitter: '   '])
        assert false: 'a blank submitter must be rejected'
    } catch (IllegalArgumentException e) {
        assert e.message.contains('terraformApprovalSubmitter must not be empty'): e.message
    }

    // the valid defaults still build without error
    assert newConfig([:]).terraformApprovalTimeout == 30
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
    child.parseClass(new File(root, 'vars/deployKubernetes.groovy'))
    child.parseClass(new File(root, 'vars/verifyIngress.groovy'))
    child.parseClass(new File(root, 'vars/smokeTests.groovy'))
    child.parseClass(new File(root, 'vars/promoteEnvironment.groovy'))
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
    assert !block.contains('terraformApply('): 'the plan stages must not run apply'
}

test('captures the checkout result and publishes the commit before the plan (source level)') {
    String text = new File(root, 'vars/circleguardPipeline.groovy').text

    int checkout = text.indexOf('Map scmVars = checkout scm')
    assert checkout > 0: 'the return value of the checkout must be captured'
    assert text.count('checkout scm') == 1: 'exactly one checkout, never a second one'

    int publish = text.indexOf('env.GIT_COMMIT = scmVars.GIT_COMMIT')
    assert publish > checkout: 'the commit must be published after the checkout'
    assert publish < text.indexOf("stage('Terraform plan')"):
        'the commit must reach env before the plan stage runs'

    // Published only when absent: an existing value is never overwritten, and no
    // SHA is ever fabricated (the value is the one the checkout returned).
    assert text.contains('if (!env.GIT_COMMIT && scmVars?.GIT_COMMIT)'):
        'an existing commit must never be overwritten'
    assert text.contains('if (!env.GIT_BRANCH && scmVars?.GIT_BRANCH)'):
        'an existing branch must never be overwritten'
    assert !text.contains("GIT_COMMIT = '") && !text.contains('GIT_COMMIT = "'):
        'no default or made-up commit is ever assigned'
    assert text.contains('skipDefaultCheckout()'): 'the checkout option must be kept'
    assert text.contains("sh 'git log -1"): 'the git log of the checkout must be kept'
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
    assert text.contains('env.TF_PLAN_SHA256 = plan.sha256')
    assert text.contains('env.TF_PLAN_CHANGES = plan.changes.toString()')

    int plan = text.indexOf("stage('Terraform plan')")
    int apply = text.indexOf("stage('Terraform apply')")
    int publish = text.indexOf("stage('Publish images')")
    assert plan > 0 && apply > plan && publish > apply:
        "wrong order: plan=${plan} apply=${apply} publish=${publish}"

    String block = text.substring(apply, publish)
    // flag AND branch: PRs never receive the AWS credential
    assert block.contains('cfg.terraformApply && cfg.terraformApplyBranches.contains(env.BRANCH_NAME)')
    // stage budget is 2x the command timeout; the whole-build budget is a single
    // source of truth, also used by the guard of the approval stage
    assert block.contains('timeout(time: cfg.terraformApplyTimeout * 2, unit:')
    assert text.contains('final int pipelineTimeoutMinutes = 120')
    assert text.contains('timeout(time: pipelineTimeoutMinutes, unit:')
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

println 'terraform targets & approval (S5)'

test('maps each branch to a fixed target, with no arbitrary branch/root pairing') {
    def cfg = newConfig([:])
    def h = newStep('circleguardPipeline')

    assert h.script.terraformTarget(cfg, 'dev') == [name: 'dev',
                                                    root: 'infra/terraform/envs/dev']
    assert h.script.terraformTarget(cfg, 'main') == [name: 'prod',
                                                     root: 'infra/terraform/envs/prod']
    // a DEV branch never resolves to the PROD target (and PROD only from main)
    assert h.script.terraformTarget(cfg, 'dev')?.name != 'prod'
    // PRs and feature branches drive no target at all
    assert h.script.terraformTarget(cfg, 'PR-7') == null
    assert h.script.terraformTarget(cfg, 'feature/x') == null
    assert h.script.terraformTarget(cfg, null) == null
}

test('rejects a PROD target outside main and a branch configured for both targets') {
    def h = newStep('circleguardPipeline')

    def prodElsewhere = newConfig([terraformApplyProdBranches: ['staging']])
    try {
        h.script.terraformTarget(prodElsewhere, 'staging')
        assert false: 'PROD from a branch other than main must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains("only allowed from 'main'"): e.message
        assert e.message.contains('infra/terraform/envs/prod'): 'the message must name the root'
    }

    def both = newConfig([terraformApplyBranches: ['dev'],
                          terraformApplyProdBranches: ['dev']])
    try {
        h.script.terraformTarget(both, 'dev')
        assert false: 'a branch configured for both targets must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('BOTH'): e.message
        assert e.message.contains('refusing to pick a root arbitrarily'): e.message
    }
}

test('keeps the DEV flow and never calls the approval from it') {
    String text = new File(root, 'vars/circleguardPipeline.groovy').text
    int devPlan = text.indexOf("stage('Terraform plan')")
    int devApply = text.indexOf("stage('Terraform apply')")
    int prodApply = text.indexOf("stage('Terraform apply PROD')")
    assert devPlan > 0 && devApply > devPlan && prodApply > devApply

    String devPlanBlock = text.substring(devPlan, devApply)
    assert devPlanBlock.contains('Map plan = terraformPlan(')
    assert devPlanBlock.contains('root: cfg.terraformPlanRoot')
    assert devPlanBlock.contains('cfg.terraformPlan && cfg.terraformPlanBranches.contains(env.BRANCH_NAME)')

    String devApplyBlock = text.substring(devApply, prodApply)
    assert devApplyBlock.contains('cfg.terraformApply && cfg.terraformApplyBranches.contains(env.BRANCH_NAME)')
    assert devApplyBlock.contains('root: cfg.terraformApplyRoot')
    assert devApplyBlock.contains('requireApproval: false'): 'DEV must state that it needs no approval'
    assert !devApplyBlock.contains('requireApproval: true')
    assert !devApplyBlock.contains('terraformApproval('): 'DEV never invokes the approval step'
}

test('requests the approval for PROD between the plan and the apply') {
    String text = new File(root, 'vars/circleguardPipeline.groovy').text
    int planProd = text.indexOf("stage('Terraform plan PROD')")
    int approval = text.indexOf("stage('Terraform approval')")
    int applyProd = text.indexOf("stage('Terraform apply PROD')")
    int publish = text.indexOf("stage('Publish images')")
    assert planProd > 0 && approval > planProd && applyProd > approval && publish > applyProd:
        "wrong order: planProd=${planProd} approval=${approval} applyProd=${applyProd} publish=${publish}"

    String planBlock = text.substring(planProd, approval)
    assert planBlock.contains('cfg.terraformApplyProd && cfg.terraformPlan &&')
    assert planBlock.contains("terraformTarget(cfg, env.BRANCH_NAME)?.name == 'prod'")
    assert planBlock.contains('root: target.root'): 'the PROD root comes from the resolved target'
    assert planBlock.contains('env.TF_PLAN_SHA256 = plan.sha256')

    String approvalBlock = text.substring(approval, applyProd)
    assert approvalBlock.contains('cfg.terraformApproval && cfg.terraformApprovalProd')
    assert approvalBlock.contains("terraformTarget(cfg, env.BRANCH_NAME)?.name == 'prod'")
    assert approvalBlock.contains("env.TF_PLAN_CHANGES == 'true'"): 'no approval without changes'
    assert approvalBlock.contains('requireApprovalTimeLeft(pipelineStartedAtMs, pipelineTimeoutMinutes,')
    assert approvalBlock.contains('submitter: cfg.terraformApprovalSubmitter')
    assert approvalBlock.contains('timeout: cfg.terraformApprovalTimeout')
    assert approvalBlock.contains('maxAgeMinutes: cfg.terraformApprovalMaxAgeMinutes')
    assert approvalBlock.contains('env.TF_APPROVED_TARGET = target.name')
    assert !approvalBlock.contains('catchError'): 'an interrupted approval must stop the pipeline'
    assert !approvalBlock.contains('try {'): 'nothing about the approval is swallowed'

    // with the approval switches ON, main resolves to the PROD target
    def cfgOn = newConfig([terraformApproval: true, terraformApprovalProd: true,
                           terraformApplyProd: true])
    def h = newStep('circleguardPipeline')
    assert h.script.terraformTarget(cfgOn, 'main')?.name == 'prod'
}

test('gates the PROD apply on the approval and passes the approval settings') {
    String text = new File(root, 'vars/circleguardPipeline.groovy').text
    int applyProd = text.indexOf("stage('Terraform apply PROD')")
    int publish = text.indexOf("stage('Publish images')")
    assert applyProd > 0 && publish > applyProd
    String block = text.substring(applyProd, publish)

    assert block.contains('cfg.terraformApplyProd && env.TF_PLAN_CHANGES ==')
    assert block.contains("terraformTarget(cfg, env.BRANCH_NAME)?.name == 'prod'")
    assert block.contains("env.TF_APPROVED_TARGET != 'prod'"):
        'an explicit refusal when no approval was recorded'
    assert block.contains('Nothing will be applied')
    assert block.contains('requireApproval: true')
    assert block.contains('maxAgeMinutes: cfg.terraformApprovalMaxAgeMinutes')
    assert block.contains('root: target.root')
}

test('does not request the approval without a full window left') {
    def h = newStep('circleguardPipeline')
    long now = System.currentTimeMillis()

    // 95 min elapsed of a 120 min budget -> 25 min left, less than the 30 required
    try {
        h.script.requireApprovalTimeLeft(now - 95L * 60_000L, 120, 30, now)
        assert false: 'an insufficient budget must fail before the input'
    } catch (RuntimeException e) {
        assert e.message.contains('NOT requesting the approval'): e.message
        assert e.message.contains('NOT applying anything'): e.message
        assert e.message.contains('25 minute(s) left'): e.message
    }
    assert h.sh.isEmpty(): 'nothing must run'

    // 10 min elapsed -> 110 min left, plenty of room for a 30 minute approval
    h.script.requireApprovalTimeLeft(now - 10L * 60_000L, 120, 30, now)
    assert h.logs.any { it.contains('110 minute(s) left of the 120-minute build budget') }: h.logs
}

test('keeps the image publishing stage unchanged') {
    String text = new File(root, 'vars/circleguardPipeline.groovy').text
    int publish = text.indexOf("stage('Publish images')")
    int deploy = text.indexOf("stage('Deploy')")
    assert publish > 0 && deploy > publish
    String block = text.substring(publish, deploy)

    assert block.contains('cfg.publish && cfg.publishBranches.contains(env.BRANCH_NAME)')
    assert block.contains('scanVulnerabilities: cfg.trivyImageScan')
    assert block.contains('registry: cfg.registry')
    assert block.contains('images: cfg.images')
    assert !block.contains('terraformApproval')
    assert !block.contains('requireApproval')
    assert !block.contains('Terraform')
}

test('PROD approval and apply are disabled by default and gated by their switches') {
    def cfg = newConfig([:])
    assert cfg.terraformApplyProd == false: 'PROD apply must stay off'
    assert cfg.terraformApproval == false: 'the approval must stay off'
    assert cfg.terraformApprovalProd == false: 'the PROD approval must stay off'
    assert cfg.terraformApplyProdRoot == 'infra/terraform/envs/prod'
    assert cfg.terraformApplyProdBranches == ['main']

    String text = new File(root, 'vars/circleguardPipeline.groovy').text
    String approvalBlock = text.substring(text.indexOf("stage('Terraform approval')"),
                                          text.indexOf("stage('Terraform apply PROD')"))
    // both switches are required, so the stage cannot be selected with the defaults
    assert approvalBlock.contains('cfg.terraformApproval && cfg.terraformApprovalProd')
    String planBlock = text.substring(text.indexOf("stage('Terraform plan PROD')"),
                                      text.indexOf("stage('Terraform approval')"))
    assert planBlock.contains('cfg.terraformApplyProd && cfg.terraformPlan &&')
    assert planBlock.contains("terraformTarget(cfg, env.BRANCH_NAME)?.name == 'prod'")
}

println 'approval window & gate (S5 corrections)'

// Extracts the `when { ... }` of a stage so its conditions can be asserted as text
def stageWhen = { String text, String name ->
    int start = text.indexOf("stage('${name}')")
    assert start > 0: "stage ${name} not found"
    int end = text.indexOf('options {', start)
    assert end > start: "options of ${name} not found"
    text.substring(start, end)
}
String pipelineSource = new File(root, 'vars/circleguardPipeline.groovy').text

test('allows the approval with exactly the required window left') {
    def h = newStep('circleguardPipeline')
    long now = System.currentTimeMillis()
    // 120 min budget - 90 min elapsed = exactly 30 min left == the window
    long started = now - (120L * 60_000L - 30L * 60_000L)
    h.script.requireApprovalTimeLeft(started, 120, 30, now)
    assert h.logs.any { it.contains('30 minute(s) left of the 120-minute build budget') }: h.logs
}

test('allows the approval with 30 minutes and 1 millisecond left') {
    def h = newStep('circleguardPipeline')
    long now = System.currentTimeMillis()
    long started = now - (120L * 60_000L - (30L * 60_000L + 1L))   // 1 ms of margin
    h.script.requireApprovalTimeLeft(started, 120, 30, now)        // must NOT throw
    assert h.logs.any { it.contains('minute(s) left of the 120-minute build budget') }: h.logs
    assert h.sh.isEmpty(): 'nothing must run'
}

test('rejects the approval with 29 minutes and 59 seconds left') {
    def h = newStep('circleguardPipeline')
    long now = System.currentTimeMillis()
    long started = now - (120L * 60_000L - (29L * 60_000L + 59L * 1000L))
    try {
        h.script.requireApprovalTimeLeft(started, 120, 30, now)
        assert false: 'one second short of the window must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('29 minute(s) left'): e.message
        assert e.message.contains('NOT requesting the approval'): e.message
        assert e.message.contains('NOT applying anything'): e.message
    }
    assert h.sh.isEmpty(): 'nothing must run'
}

test('rejects the approval with 29 minutes and 59.999 seconds left') {
    def h = newStep('circleguardPipeline')
    long now = System.currentTimeMillis()
    long started = now - (120L * 60_000L - (29L * 60_000L + 59_999L))
    try {
        h.script.requireApprovalTimeLeft(started, 120, 30, now)
        assert false: 'a millisecond short of the window must be rejected'
    } catch (RuntimeException e) {
        // the decision used exact milliseconds; the message only rounds down
        assert e.message.contains('29 minute(s) left'): e.message
        assert e.message.contains('NOT requesting the approval'): e.message
    }
    assert h.sh.isEmpty(): 'nothing must run'
}

test('rejects a non positive budget or approval window') {
    def h = newStep('circleguardPipeline')
    long now = System.currentTimeMillis()

    [[0, 30], [-5, 30], [120, 0], [120, -1]].each { List<Integer> pair ->
        int budget = pair[0]
        int approval = pair[1]
        try {
            h.script.requireApprovalTimeLeft(now - 60_000L, budget, approval, now)
            assert false: "budget=${budget} approval=${approval} must be rejected"
        } catch (RuntimeException e) {
            if (budget <= 0) {
                assert e.message.contains('build budget must be > 0 minutes'): e.message
            } else {
                assert e.message.contains('approval window must be > 0 minutes'): e.message
            }
        }
    }
    assert h.sh.isEmpty(): 'nothing must run'
}

test('rejects a negative elapsed time') {
    def h = newStep('circleguardPipeline')
    long now = System.currentTimeMillis()
    try {
        h.script.requireApprovalTimeLeft(now + 60_000L, 120, 30, now)  // started in the future
        assert false: 'a negative elapsed time must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('elapsed time is negative'): e.message
    }
    assert h.sh.isEmpty(): 'nothing must run'
}

test('does not request the approval when the PROD apply switch is off') {
    String gate = stageWhen(pipelineSource, 'Terraform approval')
    // even with BOTH approval switches on, the stage cannot activate without it
    assert gate.contains('cfg.terraformApplyProd'): gate
    assert gate.contains('cfg.terraformApproval && cfg.terraformApprovalProd'): gate
    def cfg = newConfig([terraformApproval: true, terraformApprovalProd: true])
    assert cfg.terraformApproval == true
    assert cfg.terraformApprovalProd == true
    assert cfg.terraformApplyProd == false: 'the PROD apply switch stays off by default'
}

test('requests the approval with the three switches, the PROD target and changes') {
    String gate = stageWhen(pipelineSource, 'Terraform approval')
    assert gate.contains('cfg.terraformApplyProd && cfg.terraformApproval && cfg.terraformApprovalProd'): gate
    assert gate.contains("terraformTarget(cfg, env.BRANCH_NAME)?.name == 'prod'"): gate
    assert gate.contains("env.TF_PLAN_CHANGES == 'true'"): gate

    def cfgOn = newConfig([terraformApproval: true, terraformApprovalProd: true,
                           terraformApplyProd: true])
    def h = newStep('circleguardPipeline')
    assert h.script.terraformTarget(cfgOn, 'main')?.name == 'prod': 'main must resolve to PROD'
}

test('never requests the approval for DEV') {
    String gate = stageWhen(pipelineSource, 'Terraform approval')
    assert gate.contains("terraformTarget(cfg, env.BRANCH_NAME)?.name == 'prod'"): gate

    def h = newStep('circleguardPipeline')
    assert h.script.terraformTarget(newConfig([:]), 'dev')?.name == 'dev': 'dev resolves to DEV'
    assert h.script.terraformTarget(newConfig([:]), 'dev')?.name != 'prod'
}

test('never requests the approval when the plan has no changes') {
    String gate = stageWhen(pipelineSource, 'Terraform approval')
    assert gate.contains("env.TF_PLAN_CHANGES == 'true'"): gate

    // the apply stage carries the same condition, so it cannot run either
    String applyGate = pipelineSource.substring(pipelineSource.indexOf("stage('Terraform apply PROD')"),
                                                pipelineSource.indexOf("stage('Publish images')"))
    assert applyGate.contains("env.TF_PLAN_CHANGES == 'true'"):
        'the PROD apply must be gated on the changes as well'
}

test('the PROD apply cannot run without a recorded approval') {
    String applyBlock = pipelineSource.substring(pipelineSource.indexOf("stage('Terraform apply PROD')"),
                                                 pipelineSource.indexOf("stage('Publish images')"))
    assert applyBlock.contains("env.TF_APPROVED_TARGET != 'prod'"): 'explicit refusal'
    assert applyBlock.contains('Nothing will be applied')
    assert applyBlock.contains('requireApproval: true')
    assert applyBlock.contains('maxAgeMinutes: cfg.terraformApprovalMaxAgeMinutes')
    assert applyBlock.contains('cfg.terraformApplyProd')
}

println 'runE2E'
test('mounts only the job workspace with volume-subpath and keeps the reports') {
    def h = newStep('runE2E')
    h.script.call(baseUrl: 'http://44.212.47.173:8081')

    assert h.sh.size() == 2: "expected E2E evidence cleanup and docker run, got ${h.sh.size()}"
    assert h.sh[0] == "rm -f 'tests/e2e-playwright/results.xml' && " +
                      "rm -rf 'tests/e2e-playwright/playwright-report' 'tests/e2e-playwright/test-results'": h.sh[0]
    String cmd = h.sh.find { it.contains('docker run --rm') }
    assert cmd != null: h.sh

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
    def h = newStep('runE2E', [failShContainsList: [[contains: 'docker run',
                                                     message: 'simulated container failure']]])
    try {
        h.script.call(baseUrl: 'http://44.212.47.173:8081')
        assert false: 'a failing container must fail the step'
    } catch (RuntimeException e) {
        assert e.message.contains('simulated container failure'): e.message
    }
    // reports are still collected before the original failure is rethrown
    assert h.junit == ['tests/e2e-playwright/results.xml']: h.junit
    assert h.archived.contains('tests/e2e-playwright/playwright-report/**, ' +
                               'tests/e2e-playwright/test-results/**'): h.archived
}

test('fails when Playwright produces no results.xml or an empty one') {
    String results = 'tests/e2e-playwright/results.xml'
    def missing = newStep('runE2E', [missing: [results]])
    try {
        missing.script.call(baseUrl: 'http://ingress.example')
        assert false: 'a missing results.xml must fail the step'
    } catch (RuntimeException e) {
        assert e.message.contains('missing tests/e2e-playwright/results.xml'): e.message
    }
    assert missing.junit.isEmpty()

    def empty = newStep('runE2E', [files: [(results): '   ']])
    try {
        empty.script.call(baseUrl: 'http://ingress.example')
        assert false: 'an empty results.xml must fail the step'
    } catch (RuntimeException e) {
        assert e.message.contains('empty tests/e2e-playwright/results.xml'): e.message
    }
    assert empty.junit.isEmpty()
}

test('preserves the original E2E failure when report publishing also fails') {
    def h = newStep('runE2E', [failShContainsList: [[contains: 'docker run',
                                                     message: 'simulated container failure']],
                               missing: ['tests/e2e-playwright/results.xml']])
    try {
        h.script.call(baseUrl: 'http://ingress.example')
        assert false: 'the original failure must propagate'
    } catch (RuntimeException e) {
        assert e.message.contains('simulated container failure'): e.message
        assert !e.message.contains('missing tests/e2e-playwright/results.xml'): e.message
    }
    assert h.logs.any { it.toString().contains('report publication also failed') }
}

test('escapes quotes in the E2E base URLs') {
    String tricky = "http://ingress.example/a'b"
    String escaped = tricky.replace("'", "'\\''")
    def h = newStep('runE2E')
    h.script.call(baseUrl: tricky, authBaseUrl: tricky, gatewayBaseUrl: tricky)
    String cmd = h.sh.find { it.contains('docker run') }
    assert cmd.contains("-e BASE_URL='${escaped}'")
    assert cmd.contains("-e AUTH_BASE_URL='${escaped}'")
    assert cmd.contains("-e GATEWAY_BASE_URL='${escaped}'")
}

test('deletes previous E2E evidence before Playwright and never publishes it') {
    String results = 'tests/e2e-playwright/results.xml'
    String report = 'tests/e2e-playwright/playwright-report/index.html'
    String artifacts = 'tests/e2e-playwright/test-results/failure.txt'
    File dir = newTempDir('e2e-stale-')
    File old = writeTestFile(new File(dir, results), '<testsuite name="old-build"/>')
    File oldReport = writeTestFile(new File(dir, report), 'old html report')
    File oldArtifacts = writeTestFile(new File(dir, artifacts), 'old failure context')

    def h = newStep('runE2E', [missing: [results]])
    try {
        h.script.call(baseUrl: 'http://ingress.example')
        assert false: 'a run with no new results must fail'
    } catch (RuntimeException e) {
        assert e.message.contains('missing tests/e2e-playwright/results.xml'): e.message
    }

    String cleanup = "rm -f 'tests/e2e-playwright/results.xml' && " +
                     "rm -rf 'tests/e2e-playwright/playwright-report' 'tests/e2e-playwright/test-results'"
    assert h.sh[0] == cleanup: h.sh[0]
    int dockerIndex = h.sh.findIndexOf { it.contains('docker run') }
    assert dockerIndex > 0: 'Playwright must run after the E2E evidence cleanup'
    assert runShell(h.sh[0], dir).exit == 0
    assert !old.exists(): 'the stale results.xml must be gone before the next run'
    assert !oldReport.exists(): 'the stale HTML report must be gone before the next run'
    assert !oldArtifacts.exists(): 'the stale test-results must be gone before the next run'
    assert h.junit.isEmpty(): 'stale JUnit evidence must never be published'

    def cleanupFailure = newStep('runE2E', [failShContainsList: [
        [contains: 'rm -f', message: 'CLEANUP ERROR']]])
    try {
        cleanupFailure.script.call(baseUrl: 'http://ingress.example')
        assert false: 'a failed E2E evidence cleanup must fail the step'
    } catch (RuntimeException e) {
        assert e.message.contains('could not clean previous E2E evidence'): e.message
        assert e.message.contains('CLEANUP ERROR'): e.message
    }
    assert cleanupFailure.sh.size() == 1: 'Playwright must not run after a failed cleanup'
    assert cleanupFailure.withCredentials.isEmpty(): 'no credential may be bound after a failed cleanup'
    assert cleanupFailure.junit.isEmpty(): 'stale evidence must never be published'
    assert cleanupFailure.archived.isEmpty(): 'stale evidence must never be archived'
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

println 'Kubernetes deployment'

test('deploys the build version with an explicit context and no prune') {
    def names = ['circleguard-web', 'circleguard-auth-service', 'circleguard-identity-service',
                 'circleguard-promotion-service', 'circleguard-notification-service',
                 'circleguard-form-service', 'circleguard-gateway-service',
                 'circleguard-dashboard-service', 'circleguard-file-service']
    def images = ['web', 'auth-service', 'identity-service', 'promotion-service',
                  'notification-service', 'form-service', 'gateway-service',
                  'dashboard-service', 'file-service'].collect { [name: "circleguard/${it}"] }
    def h = newStep('deployKubernetes', [env: [IMAGE_VERSION: '1.0.0-dev.15', BUILD_NUMBER: '42'],
                                        stdout: 'cg-dev'])

    h.script.call(environment: 'dev', context: 'cg-dev', namespace: 'circleguard',
                  registry: '10.20.1.230:8082', overlayPath: 'infra/k8s/overlays/dev',
                  images: images, deployments: names, rolloutTimeout: 120)

    assert h.sh.count { it.contains('kustomize edit set image') } == 9
    images.each { Map image ->
        String mapping = "'10.20.1.230:8082/${image.name}=10.20.1.230:8082/${image.name}:1.0.0-dev.15'"
        assert h.sh.any { it.contains(mapping) }: "missing ${mapping}"
    }
    assert h.sh.any { it.contains("kubectl --context 'cg-dev' --namespace 'circleguard' apply --dry-run=server -k") }
    assert h.sh.any { it.contains("kubectl --context 'cg-dev' --namespace 'circleguard' apply -k") }
    assert h.sh.every { !it.contains('--prune') }
    assert h.sh.count { it.contains('rollout status deployment/') } == 9
    assert h.sh.every { !it.contains('rollout status deployment/') || it.contains('--timeout=120s') }
    assert h.sh.any { it.contains("rm -rf 'infra/k8s/overlays/.deploy-dev-42'") }
    assert h.archived.contains('k8s/rendered-dev-42.yaml')
    assert h.withCredentials[0][0].credentialsId == 'dev-kubeconfig'
    assert h.withCredentials[0][1].credentialsId == 'dev-k8s-token'
    assert h.sh.any { it.contains('kustomize renders local files only') } ||
           new File(root, 'vars/deployKubernetes.groovy').text.contains('renders local files only')
}

test('injects the ServiceAccount token into a temporary kubeconfig without logging it') {
    def names = ['circleguard-web', 'circleguard-auth-service', 'circleguard-identity-service',
                 'circleguard-promotion-service', 'circleguard-notification-service',
                 'circleguard-form-service', 'circleguard-gateway-service',
                 'circleguard-dashboard-service', 'circleguard-file-service']
    def images = names.collect { [name: it.replace('circleguard-', 'circleguard/')] }
    String fakeToken = 'FAKE_SA_TOKEN_MUST_NOT_APPEAR'
    def h = newStep('deployKubernetes', [env: [IMAGE_VERSION: '1.0.0-dev.15', BUILD_NUMBER: '42'],
                                         stdout: 'cg-dev',
                                         credentialValues: [K8S_TOKEN: fakeToken]])

    h.script.call(environment: 'dev', context: 'cg-dev', namespace: 'circleguard',
                  registry: '10.20.1.230:8082', overlayPath: 'infra/k8s/overlays/dev',
                  images: images, deployments: names)

    Map kubeconfigCredential = h.withCredentials[0][0]
    Map tokenCredential = h.withCredentials[0][1]
    assert kubeconfigCredential.credentialsId == 'dev-kubeconfig'
    assert kubeconfigCredential.variable == 'KUBECONFIG_TEMPLATE'
    assert tokenCredential.credentialsId == 'dev-k8s-token'
    assert tokenCredential.variable == 'K8S_TOKEN'

    String tempKubeconfig = 'infra/k8s/overlays/.deploy-dev-42/kubeconfig'
    assert h.sh.any { it.contains('kubectl config view --minify --raw --kubeconfig "${KUBECONFIG_TEMPLATE}"') }
    assert h.sh.any { it.contains('ENVIRON["K8S_TOKEN"]') }
    assert h.sh.any { it.contains('chmod 600 "${K8S_KUBECONFIG_FILE}"') }
    assert h.withEnv.flatten().any { it == "KUBECONFIG=${tempKubeconfig}" }
    assert h.sh.any { it.contains('kubectl config set-context "${K8S_CONTEXT}" --user "${K8S_KUBECONFIG_USER}"') }

    String source = new File(root, 'vars/deployKubernetes.groovy').text
    assert !source.contains('set-credentials')
    assert !source.contains('--token')
    assert !source.contains('delete-user')
    assert source.contains('command -v awk')
    assert source.contains('certificate-authority-data')
    assert !h.sh.any { it.contains('--token') }

    int injection = h.sh.findIndexOf { it.contains('ENVIRON["K8S_TOKEN"]') }
    int contextCheck = h.sh.findIndexOf { it.contains('config current-context') }
    int dryRun = h.sh.findIndexOf { it.contains('apply --dry-run=server -k') }
    assert injection >= 0 && injection < contextCheck && contextCheck < dryRun

    List credentialEvidence = h.withCredentials.collect { List specs -> specs.collect { it.toString() } }.flatten()
    String allEvidence = (h.sh + h.logs + h.archived + h.withEnv +
                          h.written.collect { k, v -> "${k}=${v}" } + credentialEvidence).join('\n')
    assert !allEvidence.contains(fakeToken): 'the ServiceAccount token must never reach logs or artifacts'
}

test('rejects a missing token credential before binding any credential') {
    def h = newStep('deployKubernetes', [env: [IMAGE_VERSION: '1.0.0-dev.15', BUILD_NUMBER: '42']])
    try {
        h.script.call(environment: 'dev', context: 'cg-dev', namespace: 'circleguard',
                      registry: '10.20.1.230:8082', overlayPath: 'infra/k8s/overlays/dev',
                      k8sTokenCredentialId: '   ')
        assert false: 'a blank token credential must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('k8sTokenCredentialId is required'): e.message
    }
    assert h.withCredentials.isEmpty(): 'no credential may be bound before validation'
    assert h.sh.isEmpty()
}

test('cleans the temporary kubeconfig when token injection fails') {
    def names = ['circleguard-web', 'circleguard-auth-service', 'circleguard-identity-service',
                 'circleguard-promotion-service', 'circleguard-notification-service',
                 'circleguard-form-service', 'circleguard-gateway-service',
                 'circleguard-dashboard-service', 'circleguard-file-service']
    def images = names.collect { [name: it.replace('circleguard-', 'circleguard/')] }
    def h = newStep('deployKubernetes', [env: [IMAGE_VERSION: '1.0.0-dev.15', BUILD_NUMBER: '42'],
                                         stdout: 'cg-dev', failShContains: 'kubectl config view --minify'])
    try {
        h.script.call(environment: 'dev', context: 'cg-dev', namespace: 'circleguard',
                      registry: '10.20.1.230:8082', overlayPath: 'infra/k8s/overlays/dev',
                      images: images, deployments: names)
        assert false: 'a token injection failure must fail the deploy'
    } catch (RuntimeException e) {
        assert e.message.contains('simulated command failure'): e.message
    }
    assert h.sh.any { it.contains("rm -f 'infra/k8s/overlays/.deploy-dev-42/kubeconfig'") }
    assert h.sh.any { it.contains("rm -rf 'infra/k8s/overlays/.deploy-dev-42'") }
    assert h.sh.every { !it.contains('apply --dry-run=server -k') }
    assert h.sh.every { !it.contains(' rollout status deployment/') }
}

test('never exposes the token in real process argv and keeps the original kubeconfig unchanged') {
    def names = ['circleguard-web', 'circleguard-auth-service', 'circleguard-identity-service',
                 'circleguard-promotion-service', 'circleguard-notification-service',
                 'circleguard-form-service', 'circleguard-gateway-service',
                 'circleguard-dashboard-service', 'circleguard-file-service']
    def images = names.collect { [name: it.replace('circleguard-', 'circleguard/')] }
    String fakeToken = 'FAKE_SA_TOKEN_REAL_ARGV_MUST_NOT_APPEAR'
    String originalKubeconfig = '''apiVersion: v1
kind: Config
clusters:
- name: cg
  cluster:
    certificate-authority-data: Y2E=
    server: https://127.0.0.1
contexts:
- name: cg-dev
  context:
    cluster: cg
    user: original
current-context: cg-dev
users:
- name: original
  user: {}
'''
    File work = newTempDir('kube-argv-')
    File overlay = new File(work, 'infra/k8s/overlays/dev')
    overlay.mkdirs()
    File tempDir = new File(overlay.parentFile, '.deploy-dev-42')
    tempDir.mkdirs()
    File sourceKubeconfig = writeTestFile(new File(work, 'source-kubeconfig'), originalKubeconfig)
    File generated = new File(tempDir, 'kubeconfig')
    Map fake = fakeKubectl(work)
    File bin = fake.bin
    File argvLog = fake.argvLog

    def h = newStep('deployKubernetes', [
        env           : [IMAGE_VERSION: '1.0.0-dev.15', BUILD_NUMBER: '42'],
        stdout        : 'cg-dev',
        realShContains: ['kubectl config view --minify', 'ENVIRON["K8S_TOKEN"]',
                         'chmod 600', 'kubectl config set-context',
                         'kubectl config current-context', 'apply --dry-run=server -k',
                         'apply -k', 'rollout status deployment/'],
        realShPath    : bin.absolutePath,
        realShEnv     : [ARGV_LOG              : argvLog.absolutePath,
                         KUBECONFIG_TEMPLATE   : sourceKubeconfig.absolutePath,
                         FAKE_KUBECONFIG_CONTENT: originalKubeconfig,
                         K8S_TOKEN             : fakeToken,
                         K8S_CONTEXT           : 'cg-dev',
                         K8S_NAMESPACE         : 'circleguard',
                         K8S_KUBECONFIG_FILE   : generated.absolutePath,
                         K8S_KUBECONFIG_USER   : 'jenkins-k8s-token']
    ])

    h.script.call(environment: 'dev', context: 'cg-dev', namespace: 'circleguard',
                  registry: '10.20.1.230:8082', overlayPath: overlay.absolutePath,
                  images: images, deployments: names)

    String argv = argvLog.text
    assert argv.contains('config view --minify')
    assert !argv.contains(fakeToken): "token leaked in process argv: ${argv}"
    assert sourceKubeconfig.text == originalKubeconfig: 'the Secret file copy must remain untouched'
    assert !sourceKubeconfig.text.contains(fakeToken)
    String generatedKubeconfig = generated.text
    assert generatedKubeconfig.contains(fakeToken): 'the generated kubeconfig must carry the token'
    assert generatedKubeconfig.contains('current-context: cg-dev')
    assert generatedKubeconfig.contains('- name: cg-dev\n  context:\n    cluster: cg\n    user: jenkins-k8s-token')
    assert generatedKubeconfig.contains('- name: cg\n  cluster:\n    certificate-authority-data: Y2E=')
    assert generatedKubeconfig.contains('- name: jenkins-k8s-token\n  user:\n    token: "' + fakeToken + '"')
    assert generatedKubeconfig.count('- name: jenkins-k8s-token') == 1
    assert generatedKubeconfig.contains('- name: original')
    Set<java.nio.file.attribute.PosixFilePermission> permissions =
        java.nio.file.Files.getPosixFilePermissions(generated.toPath())
    assert permissions.contains(java.nio.file.attribute.PosixFilePermission.OWNER_READ)
    assert permissions.contains(java.nio.file.attribute.PosixFilePermission.OWNER_WRITE)
    assert !permissions.contains(java.nio.file.attribute.PosixFilePermission.GROUP_READ)
    assert !permissions.contains(java.nio.file.attribute.PosixFilePermission.OTHERS_READ)
}

test('rejects invalid token, duplicate user and kubeconfig without embedded CA') {
    def names = ['circleguard-web', 'circleguard-auth-service', 'circleguard-identity-service',
                 'circleguard-promotion-service', 'circleguard-notification-service',
                 'circleguard-form-service', 'circleguard-gateway-service',
                 'circleguard-dashboard-service', 'circleguard-file-service']
    def images = names.collect { [name: it.replace('circleguard-', 'circleguard/')] }
    String validKubeconfig = '''apiVersion: v1
kind: Config
clusters:
- name: cg
  cluster:
    certificate-authority-data: Y2E=
    server: https://127.0.0.1
contexts:
- name: cg-dev
  context:
    cluster: cg
    user: original
current-context: cg-dev
users:
- name: original
  user: {}
'''
    String duplicateUserKubeconfig = validKubeconfig + '''- name: jenkins-k8s-token
  user: {}
'''
    String noCaKubeconfig = validKubeconfig.replace('    certificate-authority-data: Y2E=\n', '')
    [
        [name: 'invalid token', token: 'BAD TOKEN', fixture: validKubeconfig,
         expected: 'unsupported characters'],
        [name: 'duplicate user', token: 'VALID.TOKEN-123', fixture: duplicateUserKubeconfig,
         expected: 'already contains user'],
        [name: 'missing CA', token: 'VALID.TOKEN-123', fixture: noCaKubeconfig,
         expected: 'certificate-authority-data']
    ].each { Map scenario ->
        File work = newTempDir('kube-harden-')
        File overlay = new File(work, 'infra/k8s/overlays/dev')
        overlay.mkdirs()
        File tempDir = new File(overlay.parentFile, '.deploy-dev-42')
        tempDir.mkdirs()
        File sourceKubeconfig = writeTestFile(new File(work, 'source-kubeconfig'), scenario.fixture)
        File generated = new File(tempDir, 'kubeconfig')
        Map fake = fakeKubectl(work)
        def h = newStep('deployKubernetes', [
            env           : [IMAGE_VERSION: '1.0.0-dev.15', BUILD_NUMBER: '42'],
            stdout        : 'cg-dev',
            realShContains: ['kubectl config view --minify'],
            realShPath    : fake.bin.absolutePath,
            realShEnv     : [ARGV_LOG               : fake.argvLog.absolutePath,
                             KUBECONFIG_TEMPLATE    : sourceKubeconfig.absolutePath,
                             FAKE_KUBECONFIG_CONTENT: scenario.fixture,
                             K8S_TOKEN              : scenario.token,
                             K8S_CONTEXT            : 'cg-dev',
                             K8S_NAMESPACE          : 'circleguard',
                             K8S_KUBECONFIG_FILE    : generated.absolutePath,
                             K8S_KUBECONFIG_USER    : 'jenkins-k8s-token']
        ])
        try {
            h.script.call(environment: 'dev', context: 'cg-dev', namespace: 'circleguard',
                          registry: '10.20.1.230:8082', overlayPath: overlay.absolutePath,
                          images: images, deployments: names)
            assert false: "${scenario.name} must fail"
        } catch (RuntimeException e) {
            assert e.message.contains(scenario.expected): "${scenario.name}: ${e.message}"
        }
        String argv = fake.argvLog.exists() ? fake.argvLog.text : ''
        assert !argv.contains(scenario.token)
        assert !h.logs.any { it.toString().contains(scenario.token) }
        assert !generated.exists() || !generated.text.contains(scenario.token)
    }
}

test('cleans the temporary kubeconfig when the server dry-run fails') {
    def names = ['circleguard-web', 'circleguard-auth-service', 'circleguard-identity-service',
                 'circleguard-promotion-service', 'circleguard-notification-service',
                 'circleguard-form-service', 'circleguard-gateway-service',
                 'circleguard-dashboard-service', 'circleguard-file-service']
    def images = names.collect { [name: it.replace('circleguard-', 'circleguard/')] }
    def h = newStep('deployKubernetes', [env: [IMAGE_VERSION: '1.0.0-dev.15', BUILD_NUMBER: '42'],
                                         stdout: 'cg-dev',
                                         failShContains: 'apply --dry-run=server -k'])
    try {
        h.script.call(environment: 'dev', context: 'cg-dev', namespace: 'circleguard',
                      registry: '10.20.1.230:8082', overlayPath: 'infra/k8s/overlays/dev',
                      images: images, deployments: names)
        assert false: 'a server dry-run failure must fail the deploy'
    } catch (RuntimeException e) {
        assert e.message.contains('simulated command failure'): e.message
    }
    assert h.sh.any { it.contains("rm -f 'infra/k8s/overlays/.deploy-dev-42/kubeconfig'") }
    assert h.sh.any { it.contains("rm -rf 'infra/k8s/overlays/.deploy-dev-42'") }
    assert h.sh.every { !it.contains(' apply -k ') }
    assert h.sh.every { !it.contains(' rollout status deployment/') }
}

test('reports a cleanup failure without hiding the original deploy error') {
    def names = ['circleguard-web', 'circleguard-auth-service', 'circleguard-identity-service',
                 'circleguard-promotion-service', 'circleguard-notification-service',
                 'circleguard-form-service', 'circleguard-gateway-service',
                 'circleguard-dashboard-service', 'circleguard-file-service']
    def images = names.collect { [name: it.replace('circleguard-', 'circleguard/')] }
    def h = newStep('deployKubernetes', [env: [IMAGE_VERSION: '1.0.0-dev.15', BUILD_NUMBER: '42'],
                                         stdout: 'cg-dev',
                                         failShContainsList: [
                                             [contains: 'apply --dry-run=server -k',
                                              message : 'ORIGINAL DEPLOY ERROR'],
                                             [contains: "rm -f 'infra/k8s/overlays/.deploy-dev-42/kubeconfig'",
                                              message : 'CLEANUP ERROR']]])
    try {
        h.script.call(environment: 'dev', context: 'cg-dev', namespace: 'circleguard',
                      registry: '10.20.1.230:8082', overlayPath: 'infra/k8s/overlays/dev',
                      images: images, deployments: names)
        assert false: 'cleanup must not hide a deploy error'
    } catch (RuntimeException e) {
        assert e.message.contains('ORIGINAL DEPLOY ERROR'): e.message
    }
    assert h.logs.any { it.toString().contains('WARNING cleanup failed') &&
                        it.toString().contains('CLEANUP ERROR') }
}

test('fails when cleanup fails after a successful deploy') {
    def names = ['circleguard-web', 'circleguard-auth-service', 'circleguard-identity-service',
                 'circleguard-promotion-service', 'circleguard-notification-service',
                 'circleguard-form-service', 'circleguard-gateway-service',
                 'circleguard-dashboard-service', 'circleguard-file-service']
    def images = names.collect { [name: it.replace('circleguard-', 'circleguard/')] }
    def h = newStep('deployKubernetes', [env: [IMAGE_VERSION: '1.0.0-dev.15', BUILD_NUMBER: '42'],
                                         stdout: 'cg-dev',
                                         failShContains: "rm -f 'infra/k8s/overlays/.deploy-dev-42/kubeconfig'",
                                         failShMessage: 'CLEANUP ERROR'])
    try {
        h.script.call(environment: 'dev', context: 'cg-dev', namespace: 'circleguard',
                      registry: '10.20.1.230:8082', overlayPath: 'infra/k8s/overlays/dev',
                      images: images, deployments: names)
        assert false: 'a cleanup failure after success must fail the deploy'
    } catch (RuntimeException e) {
        assert e.message.contains('cleanup failed after deploy'): e.message
    }
    assert h.logs.any { it.toString().contains('WARNING cleanup failed') &&
                        it.toString().contains('CLEANUP ERROR') }
}

test('apply and rollout use the manifest namespace and overrides are rejected') {
    def names = ['circleguard-web', 'circleguard-auth-service', 'circleguard-identity-service',
                 'circleguard-promotion-service', 'circleguard-notification-service',
                 'circleguard-form-service', 'circleguard-gateway-service',
                 'circleguard-dashboard-service', 'circleguard-file-service']
    def images = names.collect { [name: it.replace('circleguard-', 'circleguard/')] }
    def h = newStep('deployKubernetes', [env: [IMAGE_VERSION: '1.0.0-dev.15', BUILD_NUMBER: '42'],
                                         stdout: 'cg-dev'])

    h.script.call(environment: 'dev', context: 'cg-dev', namespace: 'circleguard',
                  registry: '10.20.1.230:8082', overlayPath: 'infra/k8s/overlays/dev',
                  images: images, deployments: names)

    String apply = h.sh.find { it.contains(' apply -k ') }
    String rollout = h.sh.find { it.contains('rollout status deployment/') }
    assert apply.contains("--namespace 'circleguard'"): apply
    assert rollout.contains("--namespace 'circleguard'"): rollout
    assert apply.contains("--context 'cg-dev'"): apply
    assert rollout.contains("--context 'cg-dev'"): rollout

    def bad = newStep('deployKubernetes', [env: [IMAGE_VERSION: '1.0.0-dev.15', BUILD_NUMBER: '42'],
                                           stdout: 'cg-dev'])
    try {
        bad.script.call(environment: 'stage', context: 'cg-stage', namespace: 'circleguard-stage',
                        registry: '10.20.1.230:8082', overlayPath: 'infra/k8s/overlays/stage',
                        images: images, deployments: names)
        assert false: 'a namespace override must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains("manifests hardcode namespace 'circleguard'"): e.message
        assert e.message.contains("'circleguard-stage' is not supported"): e.message
    }
    assert bad.sh.isEmpty(): 'nothing must run with an unsupported namespace'
}

test('rejects platform resources before archiving or touching the cluster') {
    def names = ['circleguard-web', 'circleguard-auth-service', 'circleguard-identity-service',
                 'circleguard-promotion-service', 'circleguard-notification-service',
                 'circleguard-form-service', 'circleguard-gateway-service',
                 'circleguard-dashboard-service', 'circleguard-file-service']
    def images = names.collect { [name: it.replace('circleguard-', 'circleguard/')] }
    String platformManifest = '''apiVersion: v1
kind: Namespace
metadata:
  name: circleguard-observability
---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: prometheus
  namespace: circleguard-observability
'''
    def h = newStep('deployKubernetes', [env: [IMAGE_VERSION: '1.0.0-dev.15', BUILD_NUMBER: '42'],
                                        stdout: 'cg-dev', renderedManifest: platformManifest])
    try {
        h.script.call(environment: 'dev', context: 'cg-dev', namespace: 'circleguard',
                      registry: '10.20.1.230:8082', overlayPath: 'infra/k8s/overlays/dev',
                      images: images, deployments: names)
        assert false: 'platform resources must not be applied by Jenkins'
    } catch (RuntimeException e) {
        assert e.message.contains('outside the Jenkins application allowlist'): e.message
        assert e.message.contains("namespace 'circleguard-observability' is outside 'circleguard'"): e.message
    }
    assert h.archived.isEmpty(): 'no out-of-scope manifest should be archived'
    assert h.sh.every { !it.contains('apply --dry-run=server -k') }
    assert h.sh.every { !it.contains(' apply -k ') }
    assert h.sh.every { !it.contains('rollout status deployment/') }
    assert h.sh.any { it.contains("rm -rf 'infra/k8s/overlays/.deploy-dev-42'") }
}

test('rejects rendered resources outside the circleguard namespace') {
    def names = ['circleguard-web', 'circleguard-auth-service', 'circleguard-identity-service',
                 'circleguard-promotion-service', 'circleguard-notification-service',
                 'circleguard-form-service', 'circleguard-gateway-service',
                 'circleguard-dashboard-service', 'circleguard-file-service']
    def images = names.collect { [name: it.replace('circleguard-', 'circleguard/')] }
    String badNamespaceManifest = '''apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: circleguard-ingress
---
apiVersion: v1
kind: Service
metadata:
  name: grafana
  namespace: circleguard-data
'''
    def h = newStep('deployKubernetes', [env: [IMAGE_VERSION: '1.0.0-dev.15', BUILD_NUMBER: '42'],
                                        stdout: 'cg-dev', renderedManifest: badNamespaceManifest])
    try {
        h.script.call(environment: 'dev', context: 'cg-dev', namespace: 'circleguard',
                      registry: '10.20.1.230:8082', overlayPath: 'infra/k8s/overlays/dev',
                      images: images, deployments: names)
        assert false: 'non-application namespaces must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('metadata.namespace is missing'): e.message
        assert e.message.contains("namespace 'circleguard-data' is outside 'circleguard'"): e.message
    }
    assert h.archived.isEmpty()
    assert h.sh.every { !it.contains(' apply -k ') }
}

test('rejects an empty render') {
    def names = ['circleguard-web', 'circleguard-auth-service', 'circleguard-identity-service',
                 'circleguard-promotion-service', 'circleguard-notification-service',
                 'circleguard-form-service', 'circleguard-gateway-service',
                 'circleguard-dashboard-service', 'circleguard-file-service']
    def images = names.collect { [name: it.replace('circleguard-', 'circleguard/')] }
    def h = newStep('deployKubernetes', [env: [IMAGE_VERSION: '1.0.0-dev.15', BUILD_NUMBER: '42'],
                                        stdout: 'cg-dev', renderedManifest: '   \n'])
    try {
        h.script.call(environment: 'dev', context: 'cg-dev', namespace: 'circleguard',
                      registry: '10.20.1.230:8082', overlayPath: 'infra/k8s/overlays/dev',
                      images: images, deployments: names)
        assert false: 'an empty render must never be applied'
    } catch (RuntimeException e) {
        assert e.message.contains('is empty; refusing to apply an empty manifest'): e.message
    }
    assert h.archived.isEmpty()
    assert h.sh.every { !it.contains(' apply -k ') }
}

test('validates the rendered application scope in source') {
    String text = new File(root, 'vars/deployKubernetes.groovy').text
    assert text.indexOf('validateRenderedManifest(renderedManifest') > 0
    assert text.indexOf('validateRenderedManifest(renderedManifest') < text.indexOf('archiveArtifacts')
    assert text.contains("'ConfigMap', 'Deployment', 'Service', 'Ingress', 'PersistentVolumeClaim'")
    assert !text.contains('--prune')
}

test('cleans the temporary overlay when rendering fails') {
    def names = ['circleguard-web', 'circleguard-auth-service', 'circleguard-identity-service',
                 'circleguard-promotion-service', 'circleguard-notification-service',
                 'circleguard-form-service', 'circleguard-gateway-service',
                 'circleguard-dashboard-service', 'circleguard-file-service']
    def images = names.collect { [name: it.replace('circleguard-', 'circleguard/')] }
    def h = newStep('deployKubernetes', [env: [IMAGE_VERSION: '1.0.0-dev.15', BUILD_NUMBER: '42'],
                                        stdout: 'cg-dev', failShContains: 'kubectl kustomize'])
    try {
        h.script.call(environment: 'dev', context: 'cg-dev', namespace: 'circleguard',
                      registry: '10.20.1.230:8082', overlayPath: 'infra/k8s/overlays/dev',
                      images: images, deployments: names)
        assert false: 'a rendering failure must fail the deploy'
    } catch (RuntimeException e) {
        assert e.message.contains('simulated command failure'): e.message
    }
    assert h.sh.any { it.contains("rm -rf 'infra/k8s/overlays/.deploy-dev-42'") }
    assert h.archived.isEmpty(): 'no manifest should be archived when rendering failed'
}

test('cleans the temporary overlay when apply or rollout fails') {
    def names = ['circleguard-web', 'circleguard-auth-service', 'circleguard-identity-service',
                 'circleguard-promotion-service', 'circleguard-notification-service',
                 'circleguard-form-service', 'circleguard-gateway-service',
                 'circleguard-dashboard-service', 'circleguard-file-service']
    def images = names.collect { [name: it.replace('circleguard-', 'circleguard/')] }
    ['apply -k', 'rollout status'].each { String broken ->
        def h = newStep('deployKubernetes', [env: [IMAGE_VERSION: '1.0.0-dev.15', BUILD_NUMBER: '42'],
                                            stdout: 'cg-dev', failShContains: broken])
        try {
            h.script.call(environment: 'dev', context: 'cg-dev', namespace: 'circleguard',
                          registry: '10.20.1.230:8082', overlayPath: 'infra/k8s/overlays/dev',
                          images: images, deployments: names)
            assert false: "${broken} failure must fail the deploy"
        } catch (RuntimeException e) {
            assert e.message.contains('simulated command failure'): e.message
        }
        assert h.sh.any { it.contains("rm -rf 'infra/k8s/overlays/.deploy-dev-42'") }
    }
}

test('aborts before cluster commands when the active context is wrong') {
    def names = ['circleguard-web', 'circleguard-auth-service', 'circleguard-identity-service',
                 'circleguard-promotion-service', 'circleguard-notification-service',
                 'circleguard-form-service', 'circleguard-gateway-service',
                 'circleguard-dashboard-service', 'circleguard-file-service']
    def images = names.collect { [name: it.replace('circleguard-', 'circleguard/')] }
    def h = newStep('deployKubernetes', [env: [IMAGE_VERSION: '1.0.0-dev.15', BUILD_NUMBER: '42'],
                                        stdout: 'wrong-context'])
    try {
        h.script.call(environment: 'dev', context: 'cg-dev', namespace: 'circleguard',
                      registry: '10.20.1.230:8082', overlayPath: 'infra/k8s/overlays/dev',
                      images: images, deployments: names)
        assert false: 'a context mismatch must abort the deploy'
    } catch (RuntimeException e) {
        assert e.message.contains("expected kubectl context 'cg-dev'"): e.message
    }
    assert h.sh.every { !it.contains('apply --dry-run=server -k') }
    assert h.sh.every { !it.contains('apply -k ') }
    assert h.sh.any { it.contains("rm -rf 'infra/k8s/overlays/.deploy-dev-42'") }
}

test('rejects a version argument, latest and a missing build version') {
    def noVersion = newStep('deployKubernetes')
    try {
        noVersion.script.call(version: '1.0.0-dev.15')
        assert false: 'deployKubernetes must not accept a version argument'
    } catch (RuntimeException e) {
        assert e.message.contains('env.IMAGE_VERSION only'): e.message
    }

    def latest = newStep('deployKubernetes', [env: [IMAGE_VERSION: 'latest']])
    try {
        latest.script.call(environment: 'dev', context: 'cg-dev', namespace: 'circleguard',
                           registry: '10.20.1.230:8082', overlayPath: 'infra/k8s/overlays/dev')
        assert false: 'latest must be rejected'
    } catch (RuntimeException e) {
        assert e.message.contains('must be a semantic version'): e.message
    }
    assert latest.sh.isEmpty(): 'nothing must run without a valid build version'
}

test('verifies Ingress endpoints and never accepts a 404') {
    def notFound = newStep('verifyIngress', [stdout: '404\nCURL_EXIT=0', retries: 1])
    try {
        notFound.script.call(baseUrl: 'http://ingress.example/',
                             checks: [[name: 'missing', path: '/x', expected: '404']],
                             retries: 1)
        assert false: 'a 404 must fail even when it is the expected code'
    } catch (RuntimeException e) {
        assert e.message.contains('endpoints not available'): e.message
        assert e.message.contains('missing (404)'): e.message
    }
    assert notFound.sh.any { it.contains("'http://ingress.example/x'") }
    assert notFound.sh.any { it.contains('CURL_EXIT=') }

    def ok = newStep('verifyIngress', [stdout: '401\nCURL_EXIT=0', retries: 1])
    List<Map> results = ok.script.call(baseUrl: 'http://ingress.example',
                                       checks: [[name: 'identity', path: '/api/v1/identities',
                                                 expected: '401 403']],
                                       retries: 1)
    assert results[0].ok
    assert results[0].status == '401'
    assert !results[0].transportError
    assert results[0].request == 'GET http://ingress.example/api/v1/identities'
}

test('distinguishes transport errors from HTTP codes and honours expected-code overrides') {
    def transport = newStep('verifyIngress', [stdout: '000\nCURL_EXIT=7', retries: 1])
    try {
        transport.script.call(baseUrl: 'http://ingress.example',
                              checks: [[name: 'web', path: '/', expected: '200']],
                              retries: 1)
        assert false: 'a curl transport error must fail the verification'
    } catch (RuntimeException e) {
        assert e.message.contains('curl exit 7'): e.message
        assert !e.message.contains('HTTP 000'): e.message
    }

    def override = newStep('verifyIngress', [stdout: '503\nCURL_EXIT=0', retries: 1])
    List<Map> results = override.script.call(baseUrl: 'http://ingress.example',
                                             checks: [[name: 'maintenance', path: '/health',
                                                       expected: '200']],
                                             expectedCodes: [maintenance: [503]],
                                             retries: 1)
    assert results[0].ok
    assert results[0].expected == '503'
    assert results[0].status == '503'
}

test('captures curl exit codes in a real shell and retries transport failures') {
    File dir = newTempDir('ingress-curl-')
    File bin = new File(dir, 'bin')
    File counter = new File(dir, 'counter.txt')
    writeTestFile(new File(bin, 'curl'), '''#!/usr/bin/env bash
set -u
n=0
if [ -f "$COUNTER" ]; then n=$(cat "$COUNTER"); fi
n=$((n + 1))
printf '%s' "$n" > "$COUNTER"
if [ "$n" -lt 3 ]; then
  echo 'connection refused' >&2
  exit 7
fi
printf '200'
''')
    new File(bin, 'curl').setExecutable(true)

    def h = newStep('verifyIngress', [realShContains: 'curl -s', realShCwd: dir,
                                      realShPath: bin.absolutePath,
                                      realShEnv: [COUNTER: counter.absolutePath]])
    List<Map> results = h.script.call(baseUrl: 'http://ingress.example',
                                      checks: [[name: 'web', path: '/', expected: '200']],
                                      retries: 3, intervalSeconds: 0)

    assert h.sh.count { it.contains('curl -s') } == 3
    assert counter.text.trim() == '3'
    assert results[0].ok
    assert results[0].transportError == ''
    assert results[0].status == '200'

    writeTestFile(new File(bin, 'curl'), '''#!/usr/bin/env bash
echo 'connection refused' >&2
exit 7
''')
    new File(bin, 'curl').setExecutable(true)
    def broken = newStep('verifyIngress', [realShContains: 'curl -s', realShCwd: dir,
                                           realShPath: bin.absolutePath])
    try {
        broken.script.call(baseUrl: 'http://ingress.example',
                           checks: [[name: 'web', path: '/', expected: '200']],
                           retries: 1)
        assert false: 'a persistent transport error must fail verification'
    } catch (RuntimeException e) {
        assert e.message.contains('curl exit 7'): e.message
        assert e.message.contains('web (curl exit 7)'): e.message
    }
}

test('runs smoke tests from Jenkins against the Ingress without SSH or Compose ports') {
    String output = [
        'SMOKE|web home page|GET http://ingress.example/|200|200|true|0',
        'SMOKE|web runtime configuration|GET http://ingress.example/env-config.js|200|200|true|0',
        'SMOKE|gateway validates a token|POST http://ingress.example/api/v1/gate/validate|200|200|true|0',
        'SMOKE|form lists pending surveys|GET http://ingress.example/api/v1/certificates/pending|200|200|true|0',
        'SMOKE|promotion health stats|GET http://ingress.example/api/v1/health-status/stats|200|200|true|0',
        'SMOKE|identity requires auth|GET http://ingress.example/api/v1/identities/lookup/id|401 403|401|true|0',
        'SMOKE|auth login with valid user|POST http://ingress.example/api/v1/auth/login|200|200|true|0',
        'SMOKE|auth rejects a wrong password|POST http://ingress.example/api/v1/auth/login|401|401|true|0'
    ].join('\n')
    def h = newStep('smokeTests', [stdout: output])

    List<Map> results = h.script.call(baseUrl: 'http://ingress.example/', environment: 'dev',
                                      loginCredentialsId: 'e2e-credential')

    assert results.size() == 8
    assert h.sh.any { it == 'bash smoke-tests/smoke-run.sh' }
    assert h.sh.every { !it.contains('ssh ') && !it.contains('scp ') && !it.contains(':8081') }
    assert h.withCredentials[0][0].usernameVariable == 'SMOKE_USER'
    String credentialCommand = h.sh.find { it.contains('login.json') }
    assert credentialCommand.contains('umask 077'): credentialCommand
    assert credentialCommand.contains('chmod 600 smoke-tests/login.json'): credentialCommand
    assert !credentialCommand.contains('SMOKE_PASS='): credentialCommand
    assert h.sh.any { it.contains("rm -f smoke-tests/login.json smoke-tests/login-bad.json") &&
                      it.contains("test ! -e smoke-tests/login.json") }
    String script = h.written['smoke-tests/smoke-run.sh']
    assert script.contains("'http://ingress.example/'")
    assert !script.contains('localhost:')
    assert script.contains('if [ "$code" = "404" ]; then')
    assert !script.contains('SMOKE_PASS')
    assert h.junit == ['smoke-tests/smoke-dev.xml']
    assert h.archived.contains('smoke-tests/smoke-dev.txt')
}

test('fails the build when a smoke check reports a failure') {
    String output = [
        'SMOKE|web home page|GET http://ingress.example/|200|200|true|0',
        'SMOKE|auth login with valid user|POST http://ingress.example/api/v1/auth/login|200|401|false|0'
    ].join('\n')
    def h = newStep('smokeTests', [stdout: output, loginCredentialsId: null])
    List<Map> checks = [[name: 'web home page', path: '/', expected: '200'],
                        [name: 'auth login with valid user', method: 'POST',
                         path: '/api/v1/auth/login', expected: '200']]
    try {
        h.script.call(baseUrl: 'http://ingress.example', environment: 'dev',
                      loginCredentialsId: null, checks: checks)
        assert false: 'a failing smoke check must fail the step'
    } catch (RuntimeException e) {
        assert e.message.contains('failed the smoke tests'): e.message
        assert e.message.contains('auth login with valid user'): e.message
    }
    assert h.currentBuild.description.contains('smoke tests FAILED on dev')
}

test('fails when the smoke credential files cannot be removed') {
    def h = newStep('smokeTests', [stdout: '', loginCredentialsId: null,
                                   failShContains: 'rm -f smoke-tests/login.json'])
    try {
        h.script.call(baseUrl: 'http://ingress.example', environment: 'dev',
                      loginCredentialsId: null)
        assert false: 'a failed cleanup must not be hidden'
    } catch (RuntimeException e) {
        assert e.message.contains('simulated command failure'): e.message
    }
}

test('does not trace the smoke password and keeps credential files private') {
    File dir = newTempDir('smoke-secrets-')
    new File(dir, 'smoke-tests').mkdirs()
    String canary = 'CANARY-SMOKE-SECRET'
    def h = newStep('smokeTests', [stdout: '', realShContains: 'umask 077',
                                   realShCwd: dir,
                                   realShEnv: [SMOKE_USER: 'smoke-user', SMOKE_PASS: canary]])
    try {
        h.script.call(baseUrl: 'http://ingress.example', environment: 'dev')
    } catch (RuntimeException ignored) {
    }

    String credentialCommand = h.sh.find { it.contains('umask 077') }
    assert credentialCommand.contains('set +x'): credentialCommand
    assert !h.shellOutputs[0].contains(canary): h.shellOutputs[0]
    File login = new File(dir, 'smoke-tests/login.json')
    File badLogin = new File(dir, 'smoke-tests/login-bad.json')
    assert login.exists() && badLogin.exists()
    def expectedMode = [java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                        java.nio.file.attribute.PosixFilePermission.OWNER_WRITE] as Set
    assert java.nio.file.Files.getPosixFilePermissions(login.toPath()) == expectedMode
    assert java.nio.file.Files.getPosixFilePermissions(badLogin.toPath()) == expectedMode
    assert login.text.contains(canary): 'the canary must reach the credential file, not the log'

    String cleanup = h.sh.find { it.contains('rm -f smoke-tests/login.json') }
    assert cleanup.contains('smoke-tests/body.tmp'): cleanup
    assert cleanup.contains('smoke-tests/smoke-run.sh'): cleanup
    assert runShell(cleanup, dir).exit == 0
    assert !login.exists() && !badLogin.exists()
}

test('creates a private smoke script and removes it during cleanup') {
    File dir = newTempDir('smoke-script-')
    File script = writeTestFile(new File(dir, 'smoke-tests/smoke-run.sh'),
                                '#!/usr/bin/env bash\nexit 0\n')
    File body = writeTestFile(new File(dir, 'smoke-tests/body.tmp'), 'previous-run-token')

    def privateStep = newStep('smokeTests', [stdout: '', loginCredentialsId: null,
                                              realShContains: 'chmod 600 smoke-tests/smoke-run.sh',
                                              realShCwd: dir])
    try {
        privateStep.script.call(baseUrl: 'http://ingress.example', environment: 'dev',
                                loginCredentialsId: null)
    } catch (RuntimeException ignored) {
    }
    def expectedMode = [java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                        java.nio.file.attribute.PosixFilePermission.OWNER_WRITE] as Set
    assert java.nio.file.Files.getPosixFilePermissions(script.toPath()) == expectedMode

    def cleanupStep = newStep('smokeTests', [stdout: '', loginCredentialsId: null,
                                              realShContains: 'rm -f smoke-tests/login.json',
                                              realShCwd: dir])
    try {
        cleanupStep.script.call(baseUrl: 'http://ingress.example', environment: 'dev',
                                loginCredentialsId: null)
    } catch (RuntimeException ignored) {
    }
    String cleanup = cleanupStep.sh.find { it.contains('rm -f smoke-tests/login.json') }
    assert cleanup.contains('smoke-tests/smoke-run.sh'): cleanup
    assert !script.exists(): 'smoke-run.sh must be removed during cleanup'
    assert !body.exists(): 'body.tmp must be removed during cleanup'
}

test('the smoke script removes a private body.tmp through a real shell trap') {
    File dir = newTempDir('smoke-body-')
    File bin = new File(dir, 'bin')
    File modeFile = new File(dir, 'mode.txt')
    writeTestFile(new File(bin, 'curl'), '''#!/usr/bin/env bash
set -u
out=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "-o" ]; then out="$arg"; fi
  prev="$arg"
done
printf '{"token":"fake-token"}' > "$out"
stat -c '%a' "$out" > "$MODE_FILE"
printf '200'
''')
    new File(bin, 'curl').setExecutable(true)

    List<Map> checks = [[name: 'web home page', path: '/', expected: '200']]
    def h = newStep('smokeTests', [stdout: 'SMOKE|web home page|GET http://ingress.example/|200|200|true|0'])
    h.script.call(baseUrl: 'http://ingress.example', environment: 'dev',
                  loginCredentialsId: null, checks: checks, attempts: 1)
    writeTestFile(new File(dir, 'smoke-tests/smoke-run.sh'), h.written['smoke-tests/smoke-run.sh'])

    def result = runShell('bash smoke-tests/smoke-run.sh', dir,
                          [MODE_FILE: modeFile.absolutePath], bin.absolutePath)
    assert result.exit == 0: result.stdout
    assert result.stdout.contains('SMOKE|web home page'): result.stdout
    assert modeFile.text.trim() == '600': modeFile.text
    assert !new File(dir, 'smoke-tests/body.tmp').exists(): 'body.tmp must be removed by the trap'
}

test('a smoke cleanup failure does not replace the original error') {
    def h = newStep('smokeTests', [stdout: '', loginCredentialsId: null,
                                   failShContainsList: [
                                       [contains: 'bash smoke-tests/smoke-run.sh',
                                        message: 'ORIGINAL SMOKE ERROR'],
                                       [contains: 'rm -f smoke-tests/login.json',
                                        message: 'CLEANUP ERROR']]])
    try {
        h.script.call(baseUrl: 'http://ingress.example', environment: 'dev',
                      loginCredentialsId: null)
        assert false: 'the original smoke error must propagate'
    } catch (RuntimeException e) {
        assert e.message == 'ORIGINAL SMOKE ERROR': e.message
    }
    assert h.logs.any { it.toString().contains('cleanup failed after the original error') &&
                        it.toString().contains('CLEANUP ERROR') }
}

test('promotes with Kubernetes, keeps the approval and records evidence') {
    def names = ['circleguard-web', 'circleguard-auth-service', 'circleguard-identity-service',
                 'circleguard-promotion-service', 'circleguard-notification-service',
                 'circleguard-form-service', 'circleguard-gateway-service',
                 'circleguard-dashboard-service', 'circleguard-file-service']
    def h = newStep('promoteEnvironment', [env: [IMAGE_VERSION: '1.0.0-dev.15', BUILD_NUMBER: '42',
                                                 BRANCH_NAME: 'dev']])

    h.script.call(from: 'dev', to: 'stage', version: '1.0.0-dev.15', manual: true,
                  context: 'cg-stage', namespace: 'circleguard', registry: '10.20.1.230:8082',
                   overlayPaths: [:], ingressUrls: [stage: 'http://stage.example/'],
                   kubeconfigCredentialId: 'stage-kubeconfig', k8sTokenCredentialId: 'stage-k8s-token',
                   images: [[name: 'circleguard/web']], deployments: names,
                   verifyPaths: [[name: 'web', path: '/', expected: '200']],
                   smokeTests: true, smokeCredentialsId: 'e2e-credential')

    assert h.deployKubernetesParams[0].kubeconfigCredentialId == 'stage-kubeconfig'
    assert h.deployKubernetesParams[0].k8sTokenCredentialId == 'stage-k8s-token'
    assert h.trace.any { it == 'deployKubernetes(stage)' }
    assert h.trace.any { it == 'verifyIngress(http://stage.example)' }
    assert h.trace.any { it == 'smokeTests(http://stage.example)' }
    assert h.inputs.size() == 1
    assert h.inputs[0].ok == 'Promote'
    assert h.inputs[0].submitterParameter == 'approvedBy'
    assert h.inputs[0].timeout == 120
    assert h.inputs[0].timeUnit == 'MINUTES'
    String record = h.written['promotion-record.txt']
    assert record.contains('Version      : 1.0.0-dev.15')
    assert record.contains('Route        : dev -> stage')
    assert record.contains('Condition    : manual approval (input) by admin')
    assert record.contains('Approved by  : admin')
    assert record.contains('Context      : cg-stage')
    assert record.contains('Namespace    : circleguard')
    assert record.contains('Manifest     : k8s/rendered-stage-42.yaml')
    assert h.archived.contains('promotion-record.txt')
}

test('derives kubeconfig and token credentials for each promotion target') {
    ['stage', 'prod'].each { String to ->
        def h = newStep('promoteEnvironment', [env: [IMAGE_VERSION: '1.0.0-dev.15',
                                                     BUILD_NUMBER: '42', BRANCH_NAME: 'dev']])
        h.script.call(from: (to == 'stage' ? 'dev' : 'stage'), to: to,
                      version: '1.0.0-dev.15', context: "cg-${to}", namespace: 'circleguard',
                      registry: '10.20.1.230:8082', ingressUrls: [(to): "http://${to}.example"],
                      images: [[name: 'circleguard/web']], deployments: ['circleguard-web'],
                      smokeTests: false)
        assert h.deployKubernetesParams[0].environment == to
        assert h.deployKubernetesParams[0].kubeconfigCredentialId == "${to}-kubeconfig"
        assert h.deployKubernetesParams[0].k8sTokenCredentialId == "${to}-k8s-token"
    }
}

test('requires env.IMAGE_VERSION and never derives it from the version argument') {
    def missing = newStep('promoteEnvironment', [env: [:]])
    try {
        missing.script.call(from: 'dev', to: 'stage', version: '1.0.0-dev.15')
        assert false: 'promotion without env.IMAGE_VERSION must fail'
    } catch (RuntimeException e) {
        assert e.message.contains('env.IMAGE_VERSION from this build is required'): e.message
    }
    assert missing.env.IMAGE_VERSION == null: 'params.version must never populate env.IMAGE_VERSION'

    def mismatch = newStep('promoteEnvironment', [env: [IMAGE_VERSION: '1.0.0-dev.16']])
    try {
        mismatch.script.call(from: 'dev', to: 'stage', version: '1.0.0-dev.15')
        assert false: 'a version mismatch must fail'
    } catch (RuntimeException e) {
        assert e.message.contains('differs from env.IMAGE_VERSION'): e.message
    }
}

test('a rejected or expired approval stops the promotion') {
    def h = newStep('promoteEnvironment', [env: [IMAGE_VERSION: '1.0.0-dev.15'],
                                           failInput: new RuntimeException('approval expired')])
    try {
        h.script.call(from: 'dev', to: 'stage', version: '1.0.0-dev.15', manual: true,
                      context: 'cg-stage', namespace: 'circleguard-stage',
                      ingressUrls: [stage: 'http://stage.example'])
        assert false: 'an expired approval must stop the promotion'
    } catch (RuntimeException e) {
        assert e.message.contains('approval expired'): e.message
    }
    assert h.inputs.size() == 1
    assert !h.trace.any { it.startsWith('deployKubernetes(') }
    assert !h.written.containsKey('promotion-record.txt')
}

test('rejects a manual promotion when input does not identify an approver') {
    [null, '', '   ', [approvedBy: null]].each { answer ->
        def h = newStep('promoteEnvironment', [env: [IMAGE_VERSION: '1.0.0-dev.15'],
                                               inputResult: answer])
        try {
            h.script.call(from: 'dev', to: 'stage', version: '1.0.0-dev.15', manual: true,
                          context: 'cg-stage', namespace: 'circleguard',
                          ingressUrls: [stage: 'http://stage.example'])
            assert false: "an approval without an approver must fail: ${answer}"
        } catch (RuntimeException e) {
            assert e.message.contains('manual approval did not identify an approver'): e.message
        }
        assert h.inputs.size() == 1
        assert !h.trace.any { it.startsWith('deployKubernetes(') }
        assert !h.written.containsKey('promotion-record.txt')
    }
}

test('the pipeline keeps its stages and uses only the Kubernetes deploy path') {
    String text = new File(root, 'vars/circleguardPipeline.groovy').text
    ['Checkout', 'Build', 'Tests', 'Integration tests', 'SonarQube', 'Publish images',
     'Deploy', 'Verify deployment', 'Smoke tests', 'E2E tests',
     'Promote to stage', 'Promote to prod'].each { String stage ->
        assert text.contains("stage('${stage}')"): "stage ${stage} disappeared"
    }

    assert text.contains('deployKubernetes(')
    assert text.contains('k8sTokenCredentialId: cfg.k8sTokenCredentialId ?: "${cfg.environment}-k8s-token"')
    assert text.contains('k8sTokenCredentialId: cfg.k8sTokenCredentialId,')
    assert text.contains('verifyIngress(')
    assert text.contains('smokeTests(')
    assert text.contains('baseUrl: ingressUrl')
    assert text.contains('authBaseUrl: ingressUrl')
    assert text.contains('gatewayBaseUrl: ingressUrl')
    assert text.contains("cfg.contextFor('stage')")
    assert text.contains("cfg.namespaceFor('prod')")
    assert !text.contains('deployEnvironment(')
    assert !text.contains('verifyServices(')
    assert !text.contains('DEPLOY_HOST')
    assert !text.contains('cfg.services')
    assert !text.contains(':8081')
}

test('keeps the publish registry separate from the Kubernetes registry') {
    def cfg = newConfig([deploy: true, environment: 'dev', k8sContext: 'cg-dev',
                         k8sIngressUrls: [dev: 'http://dev.example']])

    assert cfg.registry == 'localhost:8082'
    assert cfg.k8sRegistry == '10.20.1.230:8082'
    assert cfg.registry != cfg.k8sRegistry
    assert cfg.images.size() == 9
    assert cfg.images.collect { it.name }.containsAll([
        'circleguard/notification-service', 'circleguard/dashboard-service', 'circleguard/file-service'])
    assert cfg.k8sDeployments.size() == 9
    assert cfg.k8sVerifyPaths.size() == 6
    assert cfg.k8sIngressUrls.dev == 'http://dev.example'

    try {
        newConfig([deploy: true, environment: 'dev',
                   k8sIngressUrls: [dev: 'http://dev.example']])
        assert false: 'a deploy without a context must be rejected'
    } catch (IllegalArgumentException e) {
        assert e.message.contains('k8sContext is required'): e.message
    }
}

test('resolves each context but keeps the single manifest namespace') {
    def cfg = newConfig([deploy: true, promote: true, environment: 'dev',
                         k8sContext: 'cg-dev', k8sNamespace: 'circleguard',
                         k8sContexts: [stage: 'cg-stage', prod: 'cg-prod'],
                         k8sIngressUrls: [dev: 'http://dev.example',
                                          stage: 'http://stage.example',
                                          prod: 'http://prod.example']])

    assert cfg.contextFor('dev') == 'cg-dev'
    assert cfg.contextFor('stage') == 'cg-stage'
    assert cfg.contextFor('prod') == 'cg-prod'
    assert cfg.namespaceFor('dev') == 'circleguard'
    assert cfg.namespaceFor('stage') == 'circleguard'
    assert cfg.namespaceFor('prod') == 'circleguard'
}

test('keeps constructor-called config resolvers native for Jenkins CPS') {
    String source = new File(root, 'src/org/circleguard/ci/PipelineConfig.groovy').text

    assert source.contains('import com.cloudbees.groovy.cps.NonCPS'):
            'PipelineConfig must import NonCPS for methods called from its constructor'

    ['contextFor', 'namespaceFor'].each { String method ->
        String signature = "String ${method}(String environmentName)"
        int at = source.indexOf(signature)
        assert at >= 0: "${method} must exist"
        String preceding = source.substring(Math.max(0, at - 60), at)
        assert preceding.contains('@NonCPS'):
                "${method} is called from PipelineConfig.<init> and must be @NonCPS"
    }
}

test('rejects namespace configurations that disagree with the manifests') {
    try {
        newConfig([deploy: true, environment: 'dev', k8sContext: 'cg-dev',
                   k8sNamespace: 'circleguard-other',
                   k8sIngressUrls: [dev: 'http://dev.example']])
        assert false: 'a non-manifest namespace must be rejected'
    } catch (IllegalArgumentException e) {
        assert e.message.contains("manifests hardcode namespace 'circleguard'"): e.message
        assert e.message.contains('environment=dev'): e.message
    }

    try {
        newConfig([deploy: true, promote: true, environment: 'dev',
                   k8sContext: 'cg-dev',
                   k8sNamespaces: [stage: 'circleguard-stage'],
                   k8sIngressUrls: [dev: 'http://dev.example',
                                    stage: 'http://stage.example',
                                    prod: 'http://prod.example']])
        assert false: 'a stage namespace override must be rejected'
    } catch (IllegalArgumentException e) {
        assert e.message.contains("k8sNamespaces['stage'] cannot select another namespace"): e.message
    }
}

test('validates context, namespace and URL of every promotion target up front') {
    try {
        newConfig([deploy: true, promote: true, environment: 'dev',
                   k8sContext: 'cg-dev',
                   k8sContexts: [stage: 'cg-stage', prod: 'cg-prod'],
                   k8sIngressUrls: [dev: 'http://dev.example',
                                    stage: 'http://stage.example']])
        assert false: 'a missing prod ingress URL must be rejected at configuration time'
    } catch (IllegalArgumentException e) {
        assert e.message.contains("k8sIngressUrls['prod'] is required"): e.message
    }

    try {
        newConfig([deploy: true, promote: true, environment: 'dev',
                   k8sContext: '',
                   k8sContexts: [dev: 'cg-dev', stage: 'cg-stage'],
                   k8sIngressUrls: [dev: 'http://dev.example',
                                    stage: 'http://stage.example',
                                    prod: 'http://prod.example']])
        assert false: 'a missing prod context must be rejected at configuration time'
    } catch (IllegalArgumentException e) {
        assert e.message.contains('k8sContext is required'): e.message
        assert e.message.contains('environment=prod'): e.message
    }
}

test('detects the current consumer configuration blocker without changing its Jenkinsfile') {
    Map consumer = [integrationTests: true, sonar: false, publish: true,
                    deploy: true, environment: 'dev', e2e: true, promote: true,
                    services: [[name: 'web', port: 8081]],
                    discordCredentialsId: 'discord-webhook-url']
    try {
        newConfig(consumer)
        assert false: 'the current consumer config must be reported as incompatible'
    } catch (IllegalArgumentException e) {
        assert e.message.contains('k8sContext is required'): e.message
        assert e.message.contains('environment=dev'): e.message
    }
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
    assert readme.contains('## Terraform apply'): 'the section must exist'
    assert readme.contains('### PROD target and approval (S5)'): 'the PROD section must exist'
    assert readme.contains('requireApprovalTimeLeft'): 'the budget guard must be documented'
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
