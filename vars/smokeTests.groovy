import com.cloudbees.groovy.cps.NonCPS

def call(Map params = [:]) {
    String baseUrl = params.baseUrl
    String environment = params.environment ?: 'dev'
    String loginCredentialsId = params.containsKey('loginCredentialsId') ? params.loginCredentialsId : 'e2e-credential'
    int attempts = params.attempts ?: 3
    List<Map> checks = params.checks ?: defaultChecks(loginCredentialsId != null)

    if (!baseUrl?.trim()) {
        error 'smokeTests: baseUrl is required'
    }

    String root = baseUrl.replaceAll('/+$', '')
    String dir = 'smoke-tests'
    String script = "${dir}/smoke-run.sh"
    String loginFile = "${dir}/login.json"
    String badLoginFile = "${dir}/login-bad.json"
    String bodyFile = "${dir}/body.tmp"
    String output = ''
    Throwable originalFailure = null

    sh "mkdir -p ${dir}"

    try {
        writeFile file: script, text: buildScript(checks, attempts, root, bodyFile)
        sh "chmod 600 ${script}"

        if (loginCredentialsId) {
            withCredentials([usernamePassword(credentialsId: loginCredentialsId,
                                              usernameVariable: 'SMOKE_USER',
                                              passwordVariable: 'SMOKE_PASS')]) {
                sh '''
                    set +x
                    set -e
                    umask 077
                    printf '{"username":"%s","password":"%s"}' "$SMOKE_USER" "$SMOKE_PASS" > smoke-tests/login.json
                    printf '{"username":"%s","password":"%s"}' "$SMOKE_USER" "smoke-wrong-password" > smoke-tests/login-bad.json
                    chmod 600 smoke-tests/login.json smoke-tests/login-bad.json
                '''
            }
        } else {
            sh "set +x; umask 077; printf '{}' > ${loginFile}; printf '{}' > ${badLoginFile}; chmod 600 ${loginFile} ${badLoginFile}"
        }

        echo "Running ${checks.size()} smoke test(s) on ${environment} (${root})"
        output = sh(script: "bash ${script}", returnStdout: true)
    } catch (Throwable t) {
        originalFailure = t
        throw t
    } finally {
        try {
            sh "rm -f ${loginFile} ${badLoginFile} ${bodyFile} ${script} && test ! -e ${loginFile} && test ! -e ${badLoginFile} && test ! -e ${bodyFile} && test ! -e ${script}"
        } catch (Throwable cleanupFailure) {
            if (originalFailure) {
                echo "smokeTests: cleanup failed after the original error: ${cleanupFailure.message}"
            } else {
                throw cleanupFailure
            }
        }
    }

    List<Map> results = parseResults(output)
    List<Map> failed = results.findAll { !it.ok }

    writeFile file: "${dir}/smoke-${environment}.xml", text: toJUnit(environment, results)
    writeFile file: "${dir}/smoke-${environment}.txt", text: toReport(environment, root, results)
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

def defaultChecks(boolean withLogin) {
    List<Map> checks = [
        [name: 'web home page',              method: 'GET',  path: '/',                                                                       expected: '200', contains: '<html'],
        [name: 'web runtime configuration',  method: 'GET',  path: '/env-config.js',                                                          expected: '200', contains: '__ENV__'],
        [name: 'gateway validates a token',  method: 'POST', path: '/api/v1/gate/validate', body: '{"token":"smoke-test-invalid-token"}',     expected: '200', contains: 'valid'],
        [name: 'form lists pending surveys', method: 'GET',  path: '/api/v1/certificates/pending',                                            expected: '200'],
        [name: 'promotion health stats',     method: 'GET',  path: '/api/v1/health-status/stats',                                             expected: '200', contains: '{'],
        [name: 'identity requires auth',     method: 'GET',  path: '/api/v1/identities/lookup/00000000-0000-0000-0000-000000000000',          expected: '401 403'],
    ]
    if (withLogin) {
        checks << [name: 'auth login with valid user',   method: 'POST', path: '/api/v1/auth/login', bodyFile: 'smoke-tests/login.json',     expected: '200', contains: '"token"']
        checks << [name: 'auth rejects a wrong password', method: 'POST', path: '/api/v1/auth/login', bodyFile: 'smoke-tests/login-bad.json', expected: '401']
    }
    return checks
}

@NonCPS
def buildScript(List<Map> checks, int attempts, String root, String bodyFile) {
    StringBuilder sb = new StringBuilder()
    sb << '''#!/usr/bin/env bash
set +x
set -u
umask 077
: > BODY_FILE
chmod 600 BODY_FILE
trap "rm -f BODY_FILE" EXIT TERM INT HUP
check() {
  local name="$1" method="$2" url="$3" expected="$4" contains="$5" data="$6"
  local code="000" ok=false start end i
  start=$(date +%s)
  for ((i = 1; i <= ATTEMPTS; i++)); do
    if [ -n "$data" ]; then
      code=$(curl -s -o BODY_FILE -w '%{http_code}' -X "$method" -H 'Content-Type: application/json' \\
             --data "$data" --connect-timeout 5 --max-time 15 "$url" || true)
    else
      code=$(curl -s -o BODY_FILE -w '%{http_code}' -X "$method" --connect-timeout 5 --max-time 15 "$url" || true)
    fi
    chmod 600 BODY_FILE
    if [ "$code" = "404" ]; then
      ok=false
    elif echo " $expected " | grep -q " $code "; then
      if [ -z "$contains" ] || grep -qF -- "$contains" BODY_FILE; then ok=true; fi
    fi
    $ok && break
    [ "$i" -lt "$ATTEMPTS" ] && sleep 5
  done
  end=$(date +%s)
  echo "SMOKE|$name|$method $url|$expected|$code|$ok|$((end - start))"
}
'''.replace('BODY_FILE', q(bodyFile))
    sb << "ATTEMPTS=${attempts}\n"
    for (Map c : checks) {
        String path = c.path ?: '/'
        String url = root + (path.startsWith('/') ? path : "/${path}")
        String data = c.bodyFile ? "@${c.bodyFile}" : (c.body ?: '')
        sb << "check ${q(c.name ?: path)} ${q(c.method ?: 'GET')} ${q(url)} ${q(c.expected ?: '200')} ${q(c.contains ?: '')} ${q(data.toString())}\n"
    }
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
def toReport(String environment, String root, List<Map> results) {
    int passed = results.count { it.ok }
    StringBuilder sb = new StringBuilder()
    sb << "CircleGuard smoke tests\n=======================\n"
    sb << "Environment : ${environment}\n"
    sb << "Ingress     : ${root}\n"
    sb << "Build       : ${env.BUILD_URL ?: 'n/a'}\n"
    sb << "Date (UTC)  : ${new java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'").with { it.timeZone = TimeZone.getTimeZone('UTC'); it.format(new Date()) }}\n"
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
