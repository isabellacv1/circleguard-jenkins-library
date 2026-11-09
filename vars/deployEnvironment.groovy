/**
 * Deploys the images published by the pipeline to an AWS environment over SSH.
 *
 * The environment is described by a variables file in the workspace
 * (configuration as variables, nothing hardcoded in the pipeline):
 *
 *   deploy/environments/dev.env
 *     HOST=44.212.47.173
 *     SSH_USER=ubuntu
 *     REGISTRY=100.31.132.57:8082      <- the hosts pull from the public address
 *     SPRING_PROFILES_ACTIVE=dev
 *     WEB_HOST=44.212.47.173
 *
 * The files are copied to the host and docker compose is executed there with
 * `--wait`, so the step only returns once the containers report healthy/running.
 *
 * The SSH key comes from the Jenkins credential `<environment>-credential`
 * (overridable with `credentialId`); it is written to a temporary file by the
 * ssh-credentials plugin, so no ssh-agent plugin is required.
 *
 * Usage:
 *   def envCfg = deployEnvironment(environment: 'dev', version: '1.2.0-build.15.ab12cd3')
 *
 * Returns the parsed environment configuration (HOST, REGISTRY, ...).
 */
def call(Map params = [:]) {
    String environment = params.environment ?: 'dev'
    String version = params.version
    String credentialId = params.credentialId ?: "${environment}-credential"
    String remoteDir = params.remoteDir ?: 'circleguard'
    String composeFiles = params.composeFiles ?: '-f docker-compose.dev.yml -f deploy/docker-compose.yml'
    String waitTimeout = "${params.waitTimeout ?: 600}"
    String envFile = "deploy/environments/${environment}.env"

    if (!version) {
        error 'deployEnvironment: version is required'
    }
    if (version == 'latest') {
        error 'deployEnvironment: the images must be deployed with a semantic version, not latest'
    }
    if (!fileExists(envFile)) {
        error "deployEnvironment: missing ${envFile}"
    }

    Map cfg = parseEnvFile(readFile(envFile))
    if (!cfg.HOST) {
        error "deployEnvironment: HOST is not defined in ${envFile}"
    }
    if (!cfg.REGISTRY) {
        error "deployEnvironment: REGISTRY is not defined in ${envFile}"
    }

    String host = cfg.HOST
    String user = cfg.SSH_USER ?: 'ubuntu'

    echo "Environment : ${environment}"
    echo "Target      : ${user}@${host}"
    echo "Registry    : ${cfg.REGISTRY}"
    echo "Images      : ${cfg.REGISTRY}/circleguard/*:${version}"

    // The remote compose reads REGISTRY/VERSION from .env in the project directory.
    Map remoteVars = new LinkedHashMap(cfg)
    remoteVars.VERSION = version

    String remoteEnv = remoteVars.collect { k, v -> "${k}=${v}" }.join('\n') + '\n'
    writeFile file: 'deploy-env-remote.env', text: remoteEnv

    // ssh options: the key is written by the credentials plugin in a temp file
    String opts = '-i "$DEPLOY_SSH_KEY" -o StrictHostKeyChecking=accept-new ' +
                  '-o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o BatchMode=yes'

    withCredentials([sshUserPrivateKey(credentialsId: credentialId,
                                       usernameVariable: 'DEPLOY_SSH_USER',
                                       keyFileVariable: 'DEPLOY_SSH_KEY')]) {
        sh 'chmod 600 "$DEPLOY_SSH_KEY"'

        echo 'Copying the compose files to the host'
        sh "ssh ${opts} ${user}@${host} 'mkdir -p ${remoteDir}/deploy/environments'"
        sh "scp ${opts} docker-compose.dev.yml init-db.sql ${user}@${host}:${remoteDir}/"
        sh "scp ${opts} deploy/docker-compose.yml ${user}@${host}:${remoteDir}/deploy/"
        sh "scp ${opts} deploy-env-remote.env ${user}@${host}:${remoteDir}/.env"

        echo 'Pulling the images and starting the stack (waits until healthy)'
        sh "ssh ${opts} ${user}@${host} " +
           "'cd ${remoteDir} && docker compose ${composeFiles} pull && " +
           "docker compose ${composeFiles} up -d --wait --wait-timeout ${waitTimeout}'"

        sh "ssh ${opts} ${user}@${host} " +
           "'cd ${remoteDir} && docker compose ${composeFiles} ps'"
    }

    return cfg
}

/**
 * Parses a KEY=VALUE file (comments and blank lines are ignored).
 */
def parseEnvFile(String text) {
    Map result = [:]
    text.split('\n').each { line ->
        String trimmed = line.trim()
        if (!trimmed || trimmed.startsWith('#')) {
            return
        }
        int idx = trimmed.indexOf('=')
        if (idx > 0) {
            result[trimmed.substring(0, idx).trim()] = trimmed.substring(idx + 1).trim()
        }
    }
    return result
}
