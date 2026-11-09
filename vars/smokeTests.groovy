/**
 * Post-deployment smoke tests (HU-15).
 *
 * Runs a set of functional checks against a deployed environment and records the result.
 * Unlike verifyServices (any answer below 500 means "up"), every check here expects a specific
 * status code and, optionally, a fragment of the response body, so a service that answers with
 * the wrong content (404, empty page, rejected login...) fails the deployment.
 *
 * The checks run on the target host over SSH against http://localhost:<port>, so they test the
 * services where they run and do not need the application ports open to Jenkins.
 *
 * Results:
 *   - smoke-tests/smoke-<environment>.xml : JUnit report (Tests tab of the build)
 *   - smoke-tests/smoke-<environment>.txt : human readable report (build artifact)
 *   - the build fails if any check fails
 *
 * Usage:
 *   smokeTests(host: '44.212.47.173', environment: 'dev')
 */
def call(Map params = [:]) {
    String host = params.host
    String environment = params.environment ?: 'dev'
    String user = params.user ?: 'ubuntu'
    String sshCredentialId = params.sshCredentialId ?: "${environment}-credential"
    String loginCredentialsId = params.containsKey('loginCredentialsId') ? params.loginCredentialsId : 'e2e-credential'
    int attempts = params.attempts ?: 3
    List<Map> checks = params.checks ?: defaultChecks(loginCredentialsId != null)

    if (!host) {
        error 'smokeTests: host is required'
    }

    String dir = 'smoke-tests'
    String script = "${dir}/smoke-run.sh"
    String loginFile = "${dir}/login.json"
    sh "mkdir -p ${dir}"
    writeFile file: script, text: buildScript(checks, attempts)

    String opts = '-i "$SMOKE_SSH_KEY" -o StrictHostKeyChecking=accept-new ' +
                  '-o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o BatchMode=yes'
    String output = ''

    echo "Running ${checks.size()} smoke test(s) on ${environment} (${host})"

    withCredentials([sshUserPrivateKey(credentialsId: sshCredentialId,
                                       usernameVariable: 'SMOKE_SSH_USER',
                                       keyFileVariable: 'SMOKE_SSH_KEY')]) {
        sh 'chmod 600 "$SMOKE_SSH_KEY"'
        if (loginCredentialsId) {
            // The login body is written from the credential without printing it in the log
            withCredentials([usernamePassword(credentialsId: loginCredentialsId,
                                              usernameVariable: 'SMOKE_USER',
                                              passwordVariable: 'SMOKE_PASS')]) {
                sh """
                    printf '{"username":"%s","password":"%s"}' "\$SMOKE_USER" "\$SMOKE_PASS" > ${loginFile}
                    printf '{"username":"%s","password":"%s"}' "\$SMOKE_USER" "smoke-wrong-password" > ${dir}/login-bad.json
                """
            }
        } else {
            sh "printf '{}' > ${loginFile}; printf '{}' > ${dir}/login-bad.json"
        }
        try {
            sh "ssh ${opts} ${user}@${host} 'mkdir -p circleguard-smoke'"
            sh "scp ${opts} ${script} ${loginFile} ${dir}/login-bad.json ${user}@${host}:circleguard-smoke/"
            output = sh(
                script: "ssh ${opts} ${user}@${host} 'cd circleguard-smoke && bash smoke-run.sh'",
                returnStdout: true
            )
        } finally {
            sh "ssh ${opts} ${user}@${host} 'rm -rf circleguard-smoke' || true"
            sh "rm -f ${loginFile} ${dir}/login-bad.json"
        }
    }

    List<Map> results = parseResults(output)
    List<Map> failed = results.findAll { !it.ok }

    writeFile file: "${dir}/smoke-${environment}.xml", text: toJUnit(environment, results)
    writeFile file: "${dir}/smoke-${environment}.txt", text: toReport(environment, host, results)
    junit allowEmptyResults: false, testResults: "${dir}/smoke-${environment}.xml"
    archiveArtifacts artifacts: "${dir}/smoke-${environment}.txt", allowEmptyArchive: false

    results.each { r ->
        echo "  [${r.ok ? 'OK' : 'FAIL'}] ${r.name}: ${r.request} -> HTTP ${r.status} (expected ${r.expected})"
    }

    if (results.size() < checks.size()) {
        error "smokeTests: only ${results.size()} of ${checks.size()} checks reported a result"
    }
    if (failed) {
        currentBuild.description = (currentBuild.description ? currentBuild.description + ' | ' : '') +
                                   "smoke tests FAILED on ${environment}"
        error "Deployment to ${environment} failed the smoke tests: " + failed.collect { it.name }.join(', ')
    }
    echo "All ${results.size()} smoke tests passed on ${environment}."
    return results
}

/**
 * Checks for the CircleGuard core services and web app.
 * expected: accepted status codes separated by spaces. contains: fragment of the body (optional).
 */
def defaultChecks(boolean withLogin) {
    List<Map> checks = [
        [name: 'web home page',              method: 'GET',  port: 8081, path: '/',              expected: '200', contains: '<html'],
        [name: 'web runtime configuration',  method: 'GET',  port: 8081, path: '/env-config.js', expected: '200', contains: '__ENV__'],
        [name: 'gateway validates a token',  method: 'POST', port: 8087, path: '/api/v1/gate/validate', body: '{"token":"smoke-test-invalid-token"}', expected: '200', contains: 'valid'],
        [name: 'form lists pending surveys', method: 'GET',  port: 8086, path: '/api/v1/certificates/pending', expected: '200'],
        [name: 'promotion health stats',     method: 'GET',  port: 8088, path: '/api/v1/health-status/stats', expected: '200', contains: '{'],
        [name: 'identity requires auth',     method: 'GET',  port: 8083, path: '/api/v1/identities/lookup/00000000-0000-0000-0000-000000000000', expected: '401 403'],
    ]
    if (withLogin) {
        // A successful login goes through auth, LDAP, identity and PostgreSQL
        checks << [name: 'auth login with valid user',      method: 'POST', port: 8180, path: '/api/v1/auth/login', bodyFile: 'login.json',     expected: '200', contains: '"token"']
        checks << [name: 'auth rejects a wrong password',   method: 'POST', port: 8180, path: '/api/v1/auth/login', bodyFile: 'login-bad.json', expected: '401']
    }
    return checks
}

/**
 * Bash script executed on the target host. Prints one line per check:
 * SMOKE|<name>|<request>|<expected>|<status>|<ok>|<seconds>
 */
@NonCPS
def buildScript(List<Map> checks, int attempts) {
    StringBuilder sb = new StringBuilder()
    sb << '''#!/usr/bin/env bash
set -u
check() {
  local name="$1" method="$2" url="$3" expected="$4" contains="$5" data="$6"
  local code="000" ok=false start end i
  start=$(date +%s)
  for ((i = 1; i <= ATTEMPTS; i++)); do
    if [ -n "$data" ]; then
      code=$(curl -s -o body.tmp -w '%{http_code}' -X "$method" -H 'Content-Type: application/json' \\
             --data "$data" --connect-timeout 5 --max-time 15 "$url" || true)
    else
      code=$(curl -s -o body.tmp -w '%{http_code}' -X "$method" --connect-timeout 5 --max-time 15 "$url" || true)
    fi
    if echo " $expected " | grep -q " $code "; then
      if [ -z "$contains" ] || grep -qF -- "$contains" body.tmp; then ok=true; fi
    fi
    $ok && break
    [ "$i" -lt "$ATTEMPTS" ] && sleep 5
  done
  end=$(date +%s)
  echo "SMOKE|$name|$method $url|$expected|$code|$ok|$((end - start))"
}
'''
    sb << "ATTEMPTS=${attempts}\n"
    for (Map c : checks) {
        String url = "http://localhost:${c.port}${c.path ?: '/'}"
        String data = c.bodyFile ? "@${c.bodyFile}" : (c.body ?: '')
        sb << "check ${q(c.name)} ${q(c.method ?: 'GET')} ${q(url)} ${q(c.expected ?: '200')} ${q(c.contains ?: '')} ${q(data)}\n"
    }
    sb << 'rm -f body.tmp\n'
    return sb.toString()
}

@NonCPS
def q(String value) {
    return "'" + value.replace("'", "'\\''") + "'"
}

@NonCPS
def parseResults(String output) {
    List<Map> results = []
    output.readLines().each { line ->
        if (line.startsWith('SMOKE|')) {
            List<String> p = line.split('\\|', -1) as List
            results << [name: p[1], request: p[2], expected: p[3], status: p[4],
                        ok: p[5] == 'true', seconds: p[6] ?: '0']
        }
    }
    return results
}

@NonCPS
def toJUnit(String environment, List<Map> results) {
    int failures = results.count { !it.ok }
    StringBuilder sb = new StringBuilder()
    sb << '<?xml version="1.0" encoding="UTF-8"?>\n'
    sb << "<testsuite name=\"smoke-tests.${xml(environment)}\" tests=\"${results.size()}\" failures=\"${failures}\" errors=\"0\" skipped=\"0\">\n"
    results.each { r ->
        sb << "  <testcase classname=\"smoke.${xml(environment)}\" name=\"${xml(r.name)}\" time=\"${r.seconds}\">\n"
        if (!r.ok) {
            sb << "    <failure message=\"${xml("expected HTTP ${r.expected}, got ${r.status}")}\">${xml(r.request)}</failure>\n"
        }
        sb << '  </testcase>\n'
    }
    sb << '</testsuite>\n'
    return sb.toString()
}

@NonCPS
def toReport(String environment, String host, List<Map> results) {
    int passed = results.count { it.ok }
    StringBuilder sb = new StringBuilder()
    sb << "CircleGuard smoke tests\n=======================\n"
    sb << "Environment : ${environment} (${host})\n"
    sb << "Build       : ${env.BUILD_URL ?: 'n/a'}\n"
    sb << "Date (UTC)  : ${new Date().format("yyyy-MM-dd'T'HH:mm:ss'Z'", TimeZone.getTimeZone('UTC'))}\n"
    sb << "Result      : ${passed == results.size() ? 'PASSED' : 'FAILED'} (${passed}/${results.size()})\n\n"
    results.each { r ->
        sb << String.format('%-5s %-32s %-70s expected %-8s got %s%n',
                            r.ok ? 'OK' : 'FAIL', r.name, r.request, r.expected, r.status)
    }
    return sb.toString()
}

@NonCPS
def xml(String value) {
    return (value ?: '').replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                        .replace('"', '&quot;').replace("'", '&apos;')
}
