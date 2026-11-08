/**
 * Runs Gradle tasks with the project wrapper.
 *
 * Usage: gradlew 'test --continue'
 */
def call(String tasks) {
    sh 'chmod +x gradlew'
    sh "./gradlew ${tasks} --console=plain"
}
