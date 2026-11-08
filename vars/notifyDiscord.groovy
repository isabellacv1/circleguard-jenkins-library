import groovy.json.JsonOutput

/**
 * Sends a failure notification to a Discord channel using an incoming webhook.
 * The webhook URL is stored in Jenkins as a Secret text credential.
 *
 * Usage: notifyDiscord(credentialsId: 'discord-webhook-url', status: 'FAILURE')
 */
def call(Map params = [:]) {
    String credentialsId = params.credentialsId ?: 'discord-webhook-url'
    String status = params.status ?: 'FAILURE'

    if (!credentialsId) {
        echo 'notifyDiscord: no credentialsId configured, skipping notification.'
        return
    }

    String branch = env.BRANCH_NAME ?: env.GIT_BRANCH ?: 'N/A'
    String commit = env.GIT_COMMIT ?: 'N/A'
    String buildUrl = env.BUILD_URL ?: ''
    String content = "[${status}] CircleGuard CI\n" +
        "Job: ${env.JOB_NAME} #${env.BUILD_NUMBER}\n" +
        "Branch: ${branch}\n" +
        "Commit: ${commit}\n" +
        "Build: ${buildUrl}"

    writeFile file: 'discord-notification.json', text: JsonOutput.toJson([content: content])

    try {
        withCredentials([string(credentialsId: credentialsId, variable: 'DISCORD_WEBHOOK_URL')]) {
            sh 'curl -fsS -H "Content-Type: application/json" -X POST --data @discord-notification.json "$DISCORD_WEBHOOK_URL"'
        }
    } catch (Exception e) {
        echo "notifyDiscord: could not send notification (${e.message})"
    }
}
