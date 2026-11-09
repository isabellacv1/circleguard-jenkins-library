/**
 * Frees disk space on the Jenkins host after Docker work.
 *
 * The Jenkins host has a small disk and every build adds BuildKit cache, rebuilt images and
 * test container leftovers. This step removes only what nothing is using:
 *   - BuildKit cache above `keepStorage` (keeps the most recent layers so builds stay fast)
 *   - dangling images (old layers replaced by a new build)
 *   - stopped containers and unused anonymous volumes left by Testcontainers
 *
 * It never touches running containers (Jenkins, Nexus, SonarQube...), images in use or named
 * volumes, and it never fails the build.
 *
 * Usage: dockerCleanup()  or  dockerCleanup(keepStorage: '2GB')
 */
def call(Map params = [:]) {
    String keepStorage = params.keepStorage ?: '2GB'

    withEnv(["CLEANUP_KEEP_STORAGE=${keepStorage}"]) {
        sh '''#!/bin/bash
            echo "Disk before cleanup: $(df -h "$WORKSPACE" | awk 'NR==2 {print $4 " free (" $5 " used)"}')"
            docker builder prune -f --keep-storage "$CLEANUP_KEEP_STORAGE" >/dev/null 2>&1 || true
            docker image prune -f >/dev/null 2>&1 || true
            docker container prune -f >/dev/null 2>&1 || true
            docker volume prune -f >/dev/null 2>&1 || true
            echo "Disk after cleanup:  $(df -h "$WORKSPACE" | awk 'NR==2 {print $4 " free (" $5 " used)"}')"
        '''
    }
}
