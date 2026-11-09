/**
 * Verifies that the deployed services are actually available.
 *
 * The services do not expose an actuator endpoint, so the check performs a plain
 * HTTP request against every published port:
 *   - 1xx-4xx : the service is up and answering        -> OK
 *   - 5xx     : the service answers but is broken      -> failure (retried first)
 *   - 000     : nothing is listening / connection lost -> failure (retried first)
 *
 * The step retries with an interval so a container that is still starting does
 * not fail the build, and raises an error if a service never becomes available.
 *
 * Usage:
 *   verifyServices(
 *       host: '44.212.47.173',
 *       services: [[name: 'gateway', port: 8087], [name: 'web', port: 8081, path: '/']],
 *       retries: 20,
 *       intervalSeconds: 10
 *   )
 */
def call(Map params = [:]) {
    String host = params.host
    List services = params.services ?: []
    int retries = params.retries ?: 20
    int interval = params.intervalSeconds ?: 10

    if (!host) {
        error 'verifyServices: host is required'
    }
    if (!services) {
        error 'verifyServices: services list is required'
    }

    echo "Verifying ${services.size()} service(s) on ${host}"
    List<String> failed = []

    for (Map service : services) {
        String name = service.name
        String path = service.path ?: '/'
        String url = "http://${host}:${service.port}${path}"
        String last = ''
        boolean available = false

        for (int attempt = 1; attempt <= retries && !available; attempt++) {
            String code = sh(
                script: "curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 --max-time 10 '${url}' || true",
                returnStdout: true
            ).trim()

            last = code
            if (code.isInteger()) {
                int status = code as int
                available = status > 0 && status < 500
            }

            if (!available && attempt < retries) {
                echo "  ${name}: HTTP ${code} (attempt ${attempt}/${retries}), retrying in ${interval}s"
                sleep interval
            }
        }

        if (available) {
            echo "  [OK] ${name} -> ${url} (HTTP ${last})"
        } else {
            failed << "${name} -> ${url} (last status: ${last})"
            echo "  [FAIL] ${name} -> ${url} (last status: ${last})"
        }
    }

    if (failed) {
        error "Service(s) not available after ${retries} attempts:\n    " + failed.join('\n    ')
    }

    echo 'All deployed services are available.'
}
