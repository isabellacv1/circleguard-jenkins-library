/**
 * Points Testcontainers to the host Docker bridge gateway.
 *
 * Jenkins runs in its own container and starts the test containers on the host Docker
 * daemon (through /var/run/docker.sock). Those containers are siblings of Jenkins and are
 * only reachable through the gateway of the host "bridge" network.
 */
def call() {
    if (env.TESTCONTAINERS_HOST_OVERRIDE) {
        echo "Testcontainers host: ${env.TESTCONTAINERS_HOST_OVERRIDE}"
        return
    }

    String gateway = sh(
        script: "docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null || true",
        returnStdout: true
    ).trim()

    if (gateway) {
        env.TESTCONTAINERS_HOST_OVERRIDE = gateway
        echo "Testcontainers host: ${gateway}"
    } else {
        echo 'Docker bridge network not found, Testcontainers will use its default host.'
    }
}
