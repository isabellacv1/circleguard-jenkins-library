def call(Map params = [:]) {
    String baseUrl = params.baseUrl
    List<Map> checks = params.checks ?: defaultChecks()
    Map expectedCodes = params.expectedCodes ?: [:]
    int retries = params.retries ?: 10
    int interval = params.intervalSeconds ?: 5

    if (!baseUrl?.trim()) {
        error 'verifyIngress: baseUrl is required'
    }
    if (checks.isEmpty()) {
        error 'verifyIngress: checks must not be empty'
    }

    String root = baseUrl.replaceAll('/+$', '')
    List<Map> results = []

    checks.each { Map check ->
        String path = check.path ?: '/'
        String name = check.name ?: path
        String method = check.method ?: 'GET'
        Object configured = expectedCodes.containsKey(name) ? expectedCodes[name] : (check.expected ?: '200')
        List<String> expected = normalizeExpected(configured)
        String url = root + (path.startsWith('/') ? path : "/${path}")
        String last = '000'
        String transport = ''
        boolean ok = false

        for (int attempt = 1; attempt <= retries && !ok; attempt++) {
            Map answer = request(method, url, check.body)
            if (answer.transportError) {
                last = 'TRANSPORT_ERROR'
                transport = "curl exit ${answer.curlExit}"
                ok = false
            } else {
                last = answer.httpCode ?: '000'
                transport = ''
                ok = last != '404' && expected.contains(last)
            }
            if (!ok && attempt < retries) {
                sh "sleep ${interval}"
            }
        }

        results << [name          : name,
                    request       : "${method} ${url}",
                    expected      : expected.join(' '),
                    status        : last,
                    transportError: transport,
                    ok            : ok]
        echo "  [${ok ? 'OK' : 'FAIL'}] ${name}: ${method} ${url} -> ${transport ?: "HTTP ${last}"} (expected ${expected.join(' ')})"
    }

    List<Map> failed = results.findAll { !it.ok }
    if (failed) {
        error "verifyIngress: endpoints not available: " +
              failed.collect { "${it.name} (${it.transportError ?: it.status})" }.join(', ')
    }

    echo "All ${results.size()} Ingress endpoints are available."
    return results
}

Map request(String method, String url, Object body) {
    StringBuilder curl = new StringBuilder()
    curl << 'set +x\nset +e\n'
    curl << "curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 --max-time 15"
    curl << " -X ${q(method)}"
    if (body != null && body.toString().trim()) {
        curl << " -H 'Content-Type: application/json' --data ${q(body.toString())}"
    }
    curl << " ${q(url)}"
    curl << '\ncurl_exit=$?\nprintf "\\nCURL_EXIT=%s\\n" "$curl_exit"'

    List<String> lines = (sh(script: curl.toString(), returnStdout: true) ?: '').readLines()
    String httpCode = lines[0]?.trim() ?: ''
    String curlExit = lines.find { it.startsWith('CURL_EXIT=') }?.substring('CURL_EXIT='.length()) ?: ''
    return [httpCode     : (httpCode ==~ /\d{3}/) ? httpCode : '',
            transportError: curlExit && curlExit != '0',
            curlExit     : curlExit]
}

List<String> normalizeExpected(Object value) {
    List raw = (value instanceof Collection) ? value.toList() : value.toString().split(/\s+/).toList()
    List<String> codes = raw.collect { it.toString().trim() }.findAll { it ==~ /\d{3}/ }
    if (codes.isEmpty()) {
        error 'verifyIngress: expected must contain at least one 3-digit HTTP code'
    }
    return codes
}

List<Map> defaultChecks() {
    return [
        [name: 'web home',                path: '/',                                                              expected: '200'],
        [name: 'web runtime config',      path: '/env-config.js',                                                 expected: '200'],
        [name: 'gateway validates token', method: 'POST', path: '/api/v1/gate/validate', body: '{"token":"invalid"}', expected: '200'],
        [name: 'form pending surveys',    path: '/api/v1/certificates/pending',                                   expected: '200'],
        [name: 'promotion health stats',  path: '/api/v1/health-status/stats',                                    expected: '200'],
        [name: 'identity requires auth',  path: '/api/v1/identities/lookup/00000000-0000-0000-0000-000000000000', expected: '401 403'],
    ]
}

String q(String value) {
    return "'" + value.replace("'", "'\\''") + "'"
}
