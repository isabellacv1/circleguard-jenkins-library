import com.cloudbees.groovy.cps.NonCPS
import groovy.json.JsonSlurper

/**
 * OWASP ZAP **baseline scan** (spider + PASSIVE rules) of the environment this
 * build deployed, with a severity gate on the findings.
 *
 * What it is, and what it is not:
 *
 *   - baseline is PASSIVE: it crawls and inspects responses, it never attacks.
 *     It finds missing headers, weak cookies, CORS mistakes, information
 *     disclosure and answered-401 surfaces. It does NOT detect injections or
 *     reflected XSS, and the traditional spider does not execute JavaScript, so
 *     the XHR calls of the SPA are invisible without `-j` (off in this phase).
 *     Without OpenAPI the POST endpoints are not discovered either. This is
 *     declared as a limitation, never presented as full coverage.
 *   - ZAP has NO "Critical": its top level is RISK_HIGH = 3. The `Critical`
 *     bucket below exists to keep one policy across tools (Trivy, and any other
 *     future scanner), and can only be exercised with a synthetic fixture.
 *
 * Why the gate reads the JSON instead of the exit code:
 *
 *   ZAP's exit codes mean "the run produced WARN/FAIL per the -c ruleset", not
 *   "this project's policy is violated", and `-c` maps rule IDS to
 *   INFO/IGNORE/WARN/FAIL — it does not know the SEVERITY of a rule, so
 *   "block on High" cannot be expressed with it (it would be hundreds of ids,
 *   re-maintained on every ruleset update). The severity lives in the report:
 *   `site[].alerts[].riskcode`, the string "0".."4" published by the
 *   Traditional JSON Report (RISK_INFO=0 .. RISK_HIGH=3 in Alert.java).
 *
 *   Exit code interpretation (verified against docker/zap-baseline.py):
 *     0 -> clean run, 1 -> a -c rule failed, 2 -> a -c rule warned: all three
 *          are VALID RESULTS, the policy is applied to the JSON;
 *     3 -> any other failure, including "No URLs found - is the target URL
 *          accessible?" with no report written: TECHNICAL failure.
 *   So: exit code 3, missing/unreadable JSON or an empty `site` array is a
 *   technical failure and NEVER a security result; the severity always comes
 *   from `riskcode`, never from the exit code.
 *
 * Evidence and ordering (same rule as trivyImageScan):
 *
 *   Every report is named with the build number AND the target, the previous
 *   run of THIS build is removed with `rm -f` first, and everything is archived
 *   (plus published as HTML) BEFORE any `error()`/`unstable()`. The reports are
 *   never rewritten: exceptions only change the DECISION, never the content, so
 *   a suppressed finding is still visible in the HTML/JSON.
 *
 * Justified exceptions live in `.zapignore.yaml` at the workspace root (mirror
 * of `.trivyignore.yaml`), read ONLY when the file exists:
 *
 *     exceptions:
 *       - id: "10015"                       # ZAP pluginid
 *         scope: "http://host/.*"           # optional regex over the alert URL
 *         statement: >-
 *           Why this is accepted, with evidence and the accepted risk.
 *         approved_by: "reviewer"
 *         expired_at: 2027-05-17            # required: an exception without a
 *                                           # valid future date does not apply
 *
 *   Fail closed: an unparseable file, a missing/invalid `expired_at` or a
 *   past date means the exception does NOT apply and the finding blocks again.
 *   An expired exception is reported in the summary so it gets renewed or fixed.
 *
 * Container (no port is published, so the unauthenticated ZAP API stays inside
 * the container; no credential is injected, the scan is anonymous):
 *
 *   docker run --rm --user $(id -u):$(id -g) -e HOME=/tmp \
 *     --mount 'type=volume,source=circleguard-jenkins-home,destination=/zap/wrk,\
 *              volume-subpath=workspace/<job>' \
 *     -w /zap/wrk <pinned image> zap-baseline.py -t <target> -m .. -T .. -D .. \
 *     -r ..html -J ..json -x ..xml -w ..md
 *
 *   The workspace MUST be mounted at `/zap/wrk`: that is the `base_dir` the
 *   packaged script uses when it runs in Docker, so the reports land in the
 *   workspace (and are archived by Jenkins) instead of an anonymous container
 *   layer. `-T` is mandatory: without it ZAP waits forever for the passive
 *   scan. `-I` is deliberately NOT used (it only silences exit 2) and no `-c`
 *   ruleset is passed, because the policy is applied to the JSON below.
 *
 * Usage:
 *   zapBaselineScan(targets: ['http://10.20.1.230/'],
 *                   image: 'ghcr.io/zaproxy/zaproxy:2.17.0',
 *                   spiderMinutes: 1, maxTimeMinutes: 10, timeout: 15,
 *                   blockSeverities: ['High', 'Critical'],
 *                   warnSeverities: ['Medium'])
 *
 * Returns [targets: [...], counts: [Informational: n, Low: n, Medium: n,
 * High: n, Critical: n], excepted: n, expired: n, reports: [...],
 * status: 'PASS|WARN|BLOCK'].
 * Raises `error` for a technical failure (prefix TECHNICAL FAILURE) or for a
 * blocking finding; calls `unstable` for a warning-level finding.
 */
def call(Map params = [:]) {
    String image = params.image ?: 'ghcr.io/zaproxy/zaproxy:2.17.0'
    List<String> targets = []
    if (params.targets instanceof CharSequence) {
        targets << params.targets.toString()
    } else {
        (params.targets ?: []).each { Object t -> targets << t.toString() }
    }
    int spiderMinutes = params.spiderMinutes != null ? params.spiderMinutes as int : 1
    int maxTimeMinutes = params.maxTimeMinutes != null ? params.maxTimeMinutes as int : 10
    int delaySeconds = params.delaySeconds != null ? params.delaySeconds as int : 0
    boolean clientSpider = params.clientSpider ? true : false
    int timeoutMinutes = params.timeout != null ? params.timeout as int : 15
    List<String> blockSeverities = (params.blockSeverities ?: ['High', 'Critical']).collect { it.toString() }
    List<String> warnSeverities = (params.warnSeverities ?: ['Medium']).collect { it.toString() }
    String exceptionsFile = params.exceptionsFile ?: '.zapignore.yaml'
    String reportsPrefix = params.reportsPrefix ?: 'zap-report'
    String summaryPrefix = params.summaryPrefix ?: 'zap-summary'
    String volume = params.volume ?: 'circleguard-jenkins-home'

    // ---------------------------------------------------------------- guards
    if (targets.isEmpty()) {
        error 'zapBaselineScan: at least one target URL is required'
    }
    if (!env.WORKSPACE) {
        error 'zapBaselineScan: no workspace available'
    }
    // Targets and report names are interpolated into shell commands.
    targets.each { String target ->
        if (!(target ==~ /https?:\/\/[A-Za-z0-9._~:\/?#&=%+,@-]+/)) {
            error "zapBaselineScan: invalid target URL (http/https and no " +
                  "metacharacters required): ${target}"
        }
    }
    [reportsPrefix, summaryPrefix].each { String plainName ->
        if (!(plainName ==~ /[A-Za-z0-9._-]+/)) {
            error "zapBaselineScan: '${plainName}' must be a plain file name"
        }
    }
    if (exceptionsFile && !(exceptionsFile ==~ /[A-Za-z0-9._-]+/)) {
        error "zapBaselineScan: exceptionsFile must be a plain file name: ${exceptionsFile}"
    }
    // Pinned image, never :latest and never untagged.
    String lastSegment = image.tokenize('/').last()
    if (!lastSegment.contains(':') || lastSegment.endsWith(':latest')) {
        error 'zapBaselineScan: the image must be pinned to an explicit version ' +
              "(never latest): ${image}"
    }
    if (maxTimeMinutes <= 0) {
        error "zapBaselineScan: maxTimeMinutes must be > 0, got ${maxTimeMinutes}"
    }
    // The Jenkins budget has to outlive the ZAP run itself, otherwise the global
    // timeout would kill the scan in the middle and lose its evidence.
    if (timeoutMinutes <= maxTimeMinutes) {
        error "zapBaselineScan: timeout (${timeoutMinutes} min) must be GREATER than " +
              "maxTimeMinutes (${maxTimeMinutes} min)"
    }
    if (spiderMinutes < 0 || delaySeconds < 0) {
        error "zapBaselineScan: spiderMinutes (${spiderMinutes}) and delaySeconds " +
              "(${delaySeconds}) must be >= 0"
    }
    if (blockSeverities.isEmpty()) {
        error 'zapBaselineScan: blockSeverities must not be empty (nothing would block)'
    }
    blockSeverities.each { String s -> checkSeverityName(s) }
    warnSeverities.each { String s -> checkSeverityName(s) }

    // Same isolation guards as runInContainer / trivyImageScan: only the
    // workspace of THIS job reaches the container, and it must already exist.
    String subPath = env.WORKSPACE.replaceFirst('^/var/jenkins_home/', '')
    if (subPath == env.WORKSPACE || !subPath.startsWith('workspace/')) {
        error "zapBaselineScan: workspace is not under /var/jenkins_home/workspace: ${env.WORKSPACE}"
    }
    if (!fileExists(env.WORKSPACE)) {
        error "zapBaselineScan: workspace ${env.WORKSPACE} does not exist yet " +
              '(Checkout must run before this step)'
    }

    String build = env.BUILD_NUMBER ?: 'nobuild'
    String commit = env.GIT_COMMIT ?: 'unknown'
    String branch = env.BRANCH_NAME ?: 'unknown'

    // Unique per build AND per target: a report of a previous build (or of
    // another target of the same build) can never be archived as this evidence.
    Set<String> usedSlugs = [] as Set
    List<Map> plans = []
    targets.each { String target ->
        String slug = slugFor(target)
        int copy = 1
        String unique = slug
        while (usedSlugs.contains(unique)) {
            unique = "${slug}-${copy++}"
        }
        usedSlugs.add(unique)
        plans << [target: target, slug: unique,
                  html  : "${reportsPrefix}-${build}-${unique}.html",
                  json  : "${reportsPrefix}-${build}-${unique}.json",
                  xml   : "${reportsPrefix}-${build}-${unique}.xml",
                  md    : "${reportsPrefix}-${build}-${unique}.md"]
    }
    String summaryFile = "${summaryPrefix}-${build}.txt"
    String junitFile = "${summaryPrefix}-${build}.xml"

    // The evidence of a previous run of THIS build is removed first: a stale
    // file must never be echoed or archived as the result of this scan.
    List<String> allNames = [summaryFile, junitFile]
    plans.each { Map p -> allNames << p.html << p.json << p.xml << p.md }
    sh "rm -f ${allNames.collect { "'${it}'" }.join(' ')}"

    // ------------------------------------------------- pre-flight (T1)
    // Every target is checked BEFORE any container starts: an unreachable
    // objective is a technical failure, not a clean scan with zero findings.
    plans.each { Map p -> preflight(p.target) }

    // ------------------------------------------------------------- scan
    try {
        plans.each { Map p ->
            // The URL is shell-quoted: a legitimate target can contain `&`, `?`,
            // `#` or `=`, which would otherwise split (or comment out) the
            // command line. The report names are plain file names (validated
            // above) and stay unquoted, like every other step of the library.
            String command = "zap-baseline.py -t ${shellQuote(p.target)} " +
                             "-m ${spiderMinutes} " +
                             "-T ${maxTimeMinutes} -D ${delaySeconds} " +
                             "-r ${p.html} -J ${p.json} -x ${p.xml} -w ${p.md}" +
                             (clientSpider ? ' -j' : '')
            echo "zapBaselineScan: ${p.target} with ${image} " +
                 "(spider ${spiderMinutes}m, ceiling ${maxTimeMinutes}m)"
            p.status = runInContainer(image: image,
                                      command: command,
                                      mountPoint: '/zap/wrk',
                                      volume: volume,
                                      timeout: timeoutMinutes,
                                      returnStatus: true) as int
            // Written even when ZAP exits non-zero (findings are a valid
            // result): archive this target BEFORE anything can fail below.
            archiveEvidence([p.html, p.json, p.xml, p.md])
        }
    } catch (Exception e) {
        // Stage timeout or interruption: keep whatever was produced, but never
        // let the archiving of the partial evidence hide the original cause.
        try {
            archiveEvidence(allNames)
        } catch (Exception archiveFailure) {
            echo "zapBaselineScan: could not archive the partial evidence: " +
                 "${archiveFailure.message}"
        }
        throw e
    }

    publishHtmlEvidence(plans)

    // --------------------------------------------------- read the results
    List<Map> alerts = []
    plans.each { Map p ->
        if (!fileExists(p.json)) {
            technicalFailure("ZAP wrote no JSON report for ${p.target} " +
                             "(looked for ${p.json}); see the container output above")
        }
        Map parsed = parseZapReport(readFile(p.json))
        if (parsed.error) {
            technicalFailure("the report of ${p.target} is not usable: ${parsed.error}")
        }
        p.alerts = parsed.alerts
        alerts.addAll(parsed.alerts)
    }

    // ------------------------------------------------------- the policy
    List<Map> exceptions = []
    boolean exceptionsPresent = (exceptionsFile && fileExists(exceptionsFile))
    if (exceptionsPresent) {
        exceptions = parseZapExceptions(readFile(exceptionsFile))
    }
    String today = java.time.LocalDate.now().toString()
    Map evaluation = evaluate(alerts, exceptions, today,
                              blockSeverities, warnSeverities)

    String status = evaluation.blocking ? 'BLOCK'
                    : (evaluation.warning ? 'WARN' : 'PASS')

    String summary = buildSummary(build: build, branch: branch, commit: commit,
                                  image: image, plans: plans,
                                  exceptionsFile: exceptionsPresent ? exceptionsFile : null,
                                  exceptions: exceptions, evaluation: evaluation,
                                  blockSeverities: blockSeverities,
                                  warnSeverities: warnSeverities, status: status)
    writeFile file: summaryFile, text: summary
    writeFile file: junitFile, text: buildJUnit(evaluation, status)

    // Evidence first, decision second: the summary, the synthetic JUnit file and
    // every ZAP report are on disk before the build can be failed or marked
    // unstable. The reports themselves are never modified by the exceptions.
    archiveEvidence([summaryFile, junitFile] +
                    plans.collectMany { Map p -> [p.html, p.json, p.xml, p.md] })
    junit testResults: junitFile
    echo summary

    if (status == 'BLOCK') {
        error "zapBaselineScan: BLOCKED by ${evaluation.blocking.join(', ')} " +
              "(threshold ${blockSeverities.join(', ')}). Evidence archived: " +
              "${summaryFile} and ${plans.collect { it.html }.join(', ')}. " +
              (evaluation.excepted ? "${evaluation.excepted} finding(s) were " +
                                      "excepted by ${exceptionsFile}; " : '') +
              (exceptionsPresent ? "document or fix the finding, or extend " +
                                    "${exceptionsFile} with a justification and " +
                                    'an expired_at date.'
                                 : 'fix the finding or document an exception in ' +
                                    "${exceptionsFile} (statement + expired_at).")
    }
    if (status == 'WARN') {
        unstable "zapBaselineScan: ${evaluation.warning.join(', ')} finding(s) " +
                 "(threshold ${warnSeverities.join(', ')}). The build is " +
                 'unstable, not failed. See ' + summaryFile
    }
    if (status == 'PASS') {
        echo "zapBaselineScan: no blocking finding (${alerts.size()} total, " +
             "${evaluation.excepted} excepted)"
    }

    return [targets: plans.collect { it.target },
            counts : evaluation.counts,
            excepted: evaluation.excepted,
            expired : evaluation.expired,
            reports: [summaryFile, junitFile] +
                     plans.collectMany { Map p -> [p.html, p.json, p.xml, p.md] },
            status : status]
}

/**
 * Reachability check of a target BEFORE the scan. `000` (and any non 3-digit
 * answer) means curl could not talk to it: that is a technical failure, never a
 * report with zero findings.
 */
void preflight(String url) {
    String script = 'set +x\nset +e\n' +
            "curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 --max-time 15 " +
            "${shellQuote(url)}\n"
    String answer = (sh(script: script, returnStdout: true) ?: '').toString()
    String code = answer.readLines().collect { it.trim() }.find { it ==~ /\d{3}/ }
    if (code == null || code == '000') {
        technicalFailure("the target does not respond (no security finding): ${url} " +
                         "-> HTTP ${code ?: 'no answer'}")
    }
    echo "zapBaselineScan: target reachable (${code}): ${url}"
}

/** Runs ZAP in the pinned container and returns nothing (evidence is archived). */
void archiveEvidence(List<String> names) {
    List<String> present = names.findAll { fileExists(it) }
    if (present) {
        archiveArtifacts artifacts: present.join(','), allowEmptyArchive: true
    }
}

/** Publishes the HTML reports with the htmlpublisher plugin (already installed). */
void publishHtmlEvidence(List<Map> plans) {
    List<String> html = plans.collect { it.html }.findAll { fileExists(it) }
    if (html) {
        publishHTML(target: [reportDir               : '.',
                             reportFiles             : html.join(','),
                             reportName              : 'OWASP ZAP',
                             keepAll                 : true,
                             alwaysLinkToLastBuild   : true,
                             allowMissing            : true])
    }
}

void technicalFailure(String detail) {
    error 'zapBaselineScan: TECHNICAL FAILURE (this is NOT a security finding) — ' + detail
}

void checkSeverityName(String severity) {
    if (!(severity in ['Informational', 'Low', 'Medium', 'High', 'Critical'])) {
        error "zapBaselineScan: unknown severity '${severity}' (expected Informational, " +
              'Low, Medium, High or Critical)'
    }
}

String slugFor(String target) {
    String raw = target.replaceAll('[^A-Za-z0-9]+', '-').replaceAll('(^-+|-+$)', '')
    return raw.length() > 80 ? raw.substring(0, 80) : raw
}

String shellQuote(String value) {
    return "'" + value.replace("'", "'\\''") + "'"
}

/**
 * Parses the Traditional JSON Report into plain, serialisable values.
 *
 * Returns `[alerts: [...]]` or `[error: <reason>]`. An empty `site` array is an
 * error: ZAP crawled nothing, which is the "No URLs found" case. An alert whose
 * `riskcode` is missing or not "0".."4" is also an error: silently counting it
 * as Informational could hide a High behind a format change (fail closed).
 */
@NonCPS
Map parseZapReport(String text) {
    Object root
    try {
        root = new JsonSlurper().parseText(text ?: '')
    } catch (Throwable ignored) {
        return [error: 'the JSON could not be parsed']
    }
    if (!(root instanceof Map)) {
        return [error: 'the JSON root is not an object']
    }
    Object sites = ((Map) root)['site']
    if (!(sites instanceof Collection)) {
        return [error: "the report has no 'site' array"]
    }
    if (((Collection) sites).isEmpty()) {
        return [error: "the 'site' array is empty: nothing was crawled"]
    }
    List<Map> alerts = []
    for (Object site : (Collection) sites) {
        if (!(site instanceof Map)) {
            continue
        }
        Object list = ((Map) site)['alerts']
        if (!(list instanceof Collection)) {
            continue
        }
        for (Object entry : (Collection) list) {
            if (!(entry instanceof Map)) {
                continue
            }
            Map m = (Map) entry
            String risk = m['riskcode']?.toString()
            if (risk == null || !(risk in ['0', '1', '2', '3', '4'])) {
                return [error: "an alert declares riskcode='${risk}', which is not " +
                               'one of 0..4']
            }
            // Only plain Strings are copied: JsonSlurper returns LazyMap/LazyList
            // instances that must never cross a CPS suspension point.
            alerts.add([riskcode: risk,
                        pluginid: (m['pluginid'] ?: '').toString(),
                        url      : (m['url'] ?: '').toString(),
                        name     : (m['alert'] ?: '').toString()])
        }
    }
    return [alerts: alerts]
}

/**
 * Parses `.zapignore.yaml` (only the `exceptions:` block). Every field is
 * copied into a plain String map; continuation lines of folded scalars
 * (`statement: >-`) are ignored, because the statement is documentation and
 * never a condition of the gate.
 */
@NonCPS
List<Map> parseZapExceptions(String text) {
    List<Map> entries = []
    if (!text) {
        return entries
    }
    boolean inside = false
    Map current = null
    text.eachLine { String raw ->
        String line = raw.replaceAll(/\s+$/, '')
        String trimmed = line.trim()
        if (!trimmed || trimmed.startsWith('#')) {
            return
        }
        if (!(line.startsWith(' ') || line.startsWith('\t'))) {
            // A new top-level key closes the block we were reading.
            inside = trimmed.startsWith('exceptions:')
            current = null
            return
        }
        if (!inside) {
            return
        }
        String body = trimmed
        if (body.startsWith('- ')) {
            current = [:]
            entries.add(current)
            body = body.substring(2).trim()
        }
        if (current == null) {
            return
        }
        int colon = body.indexOf(':')
        if (colon < 0) {
            return
        }
        String key = body.substring(0, colon).trim()
        String value = body.substring(colon + 1).trim()
        if (value.length() > 1 &&
            ((value.startsWith('"') && value.endsWith('"')) ||
             (value.startsWith("'") && value.endsWith("'")))) {
            value = value.substring(1, value.length() - 1)
        }
        if (key in ['id', 'pluginid', 'scope', 'statement', 'approved_by', 'expired_at']) {
            current[key] = value
        }
    }
    return entries
}

/**
 * Applies the exceptions and the severity policy to every alert of every
 * target (D6: ONE aggregated decision — a High on any target blocks).
 *
 *   Informational / Low -> counted, never blocks;
 *   Medium              -> warning (unstable) unless excepted;
 *   High / Critical     -> blocks, unless excepted.
 *
 * An exception only applies when its `id` matches the ZAP pluginid, its
 * optional `scope` regex matches the alert URL and its `expired_at` is a valid
 * date that has not passed. Anything else is NOT applied (fail closed) and is
 * reported so it can be renewed.
 */
@NonCPS
Map evaluate(List<Map> alerts, List<Map> exceptions, String todayIso,
             List<String> blockSeverities, List<String> warnSeverities) {
    List<String> order = ['Informational', 'Low', 'Medium', 'High', 'Critical']
    Map counts = [:]
    order.each { String severity -> counts[severity] = 0 }
    List<String> blocking = []
    List<String> warning = []
    List<Map> exceptedFindings = []
    int excepted = 0
    int expired = 0
    int invalid = 0

    for (Map alert : alerts) {
        String severity = severityOf(alert.riskcode)
        counts[severity] = (counts[severity] as int) + 1

        Map decision = exceptionDecision(alert, exceptions, todayIso)
        if (decision.applied) {
            excepted++
            exceptedFindings.add([pluginid: alert.pluginid, name: alert.name,
                                  severity: severity, scope: decision.scope])
            continue
        }
        if (decision.expired) {
            expired++
        }
        if (decision.invalid) {
            invalid++
        }
        if (severity in blockSeverities && !(severity in blocking)) {
            blocking << severity
        }
        if (severity in warnSeverities && !(severity in warning)) {
            warning << severity
        }
    }

    return [counts      : counts,
            blocking    : blocking,
            warning     : warning,
            excepted    : excepted,
            exceptedFindings: exceptedFindings,
            expired     : expired,
            invalid     : invalid,
            total       : alerts.size()]
}

@NonCPS
String severityOf(String riskcode) {
    switch (riskcode) {
        case '0': return 'Informational'
        case '1': return 'Low'
        case '2': return 'Medium'
        case '3': return 'High'
        case '4': return 'Critical'
        default : return 'Informational'
    }
}

@NonCPS
Map exceptionDecision(Map alert, List<Map> exceptions, String todayIso) {
    Map result = [applied: false, expired: false, invalid: false, scope: '']
    if (!exceptions) {
        return result
    }
    for (Map entry : exceptions) {
        String id = (entry['id'] ?: entry['pluginid'] ?: '').toString()
        if (!id || id != alert.pluginid?.toString()) {
            continue
        }
        String scope = (entry['scope'] ?: '').toString()
        if (scope) {
            boolean matches
            try {
                matches = (alert.url ?: '').toString() ==~ scope
            } catch (Throwable badPattern) {
                result.invalid = true
                continue
            }
            if (!matches) {
                continue
            }
        }
        String expires = (entry['expired_at'] ?: '').toString()
        if (!expires) {
            // Without an expiry there is no accountable end date: refused.
            result.invalid = true
            continue
        }
        java.time.LocalDate until
        try {
            until = java.time.LocalDate.parse(expires)
        } catch (Throwable badDate) {
            result.invalid = true
            continue
        }
        java.time.LocalDate today = java.time.LocalDate.parse(todayIso)
        if (until.isBefore(today)) {
            result.expired = true
            continue
        }
        result.applied = true
        result.scope = scope
        return result
    }
    return result
}

String buildSummary(Map ctx) {
    StringBuilder sb = new StringBuilder()
    sb << 'CircleGuard - OWASP ZAP baseline scan\n'
    sb << '=====================================\n'
    sb << "build:      ${ctx.build}\n"
    sb << "branch:     ${ctx.branch}\n"
    sb << "commit:     ${ctx.commit}\n"
    sb << "image:      ${ctx.image}\n"
    sb << "generated:  ${java.time.Instant.now()}\n"
    sb << "mode:       baseline (spider + passive rules, no active attack)\n"
    sb << "policy:     block ${ctx.blockSeverities.join(', ')} | " +
        "warn ${ctx.warnSeverities.join(', ')}\n"
    if (ctx.exceptionsFile) {
        sb << "exceptions: ${ctx.exceptionsFile} (${ctx.exceptions.size()} entr" +
            "${ctx.exceptions.size() == 1 ? 'y' : 'ies'})\n"
    } else {
        sb << 'exceptions: none (no exceptions file in the workspace)\n'
    }
    sb << '\n'
    ctx.plans.each { Map p ->
        sb << "target: ${p.target}\n"
        Map counts = ctx.evaluation.counts
        // Per-target breakdown when there is more than one target.
        if (ctx.plans.size() > 1 && p.alerts != null) {
            Map local = [:]
            ['Informational', 'Low', 'Medium', 'High', 'Critical'].each { String s ->
                local[s] = 0
            }
            p.alerts.each { Map a -> local[severityOf(a.riskcode)]++ }
            sb << "  ${formatCounts(local)}\n"
        }
        sb << "  report:   ${p.html}\n"
        sb << "  zapproxy: exit ${p.status}\n"
        sb << '\n'
    }
    sb << "totals:     ${formatCounts(ctx.evaluation.counts)}\n"
    sb << "findings:   ${ctx.evaluation.total} total, " +
        "${ctx.evaluation.excepted} excepted, ${ctx.evaluation.expired} expired " +
        "exception(s), ${ctx.evaluation.invalid} unusable exception(s)\n"
    if (ctx.evaluation.exceptedFindings) {
        sb << 'excepted findings (still present in the reports):\n'
        ctx.evaluation.exceptedFindings.each { Map f ->
            sb << "  - [${f.severity}] ${f.pluginid} ${f.name}" +
                (f.scope ? " (scope ${f.scope})" : '') + '\n'
        }
    }
    sb << '\n'
    sb << "status:     ${ctx.status}\n"
    return sb.toString()
}

@NonCPS
String formatCounts(Map counts) {
    return ['Informational', 'Low', 'Medium', 'High', 'Critical']
        .collect { String s -> "${s}: ${counts[s] ?: 0}" }.join('  ')
}

/**
 * Synthetic JUnit report so the findings also show up in the Tests tab without
 * installing any plugin: one test case per severity that occurred (failing for
 * a blocking or warning severity) plus one that proves the scan ran.
 */
@NonCPS
String buildJUnit(Map evaluation, String status) {
    StringBuilder sb = new StringBuilder()
    int cases = 1
    evaluation.counts.each { String severity, Object value ->
        if ((value as int) > 0) {
            cases++
        }
    }
    int failures = totalFor(evaluation.counts, evaluation.blocking) +
                   totalFor(evaluation.counts, evaluation.warning)
    sb << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    sb << "<testsuite name=\"owasp-zap\" tests=\"${cases}\" failures=\"${failures}\" " +
        "errors=\"0\" skipped=\"0\">\n"
    sb << "  <testcase classname=\"owasp-zap\" name=\"baseline scan completed (${status})\"/>\n"
    evaluation.counts.each { String severity, Object value ->
        int n = value as int
        if (n <= 0) {
            return
        }
        boolean blocking = severity in evaluation.blocking
        boolean warning = severity in evaluation.warning
        sb << "  <testcase classname=\"owasp-zap\" name=\"${severity}: ${n} finding(s)\""
        if (blocking || warning) {
            sb << '>\n'
            sb << "    <failure message=\"${severity} finding(s): " +
                "${blocking ? 'blocks the build' : 'marks the build unstable'}\"/>\n"
            sb << "  </testcase>\n"
        } else {
            sb << "/>\n"
        }
    }
    sb << "</testsuite>\n"
    return sb.toString()
}

/** Sum of the counts of the given severities (0 when none matches). */
@NonCPS
int totalFor(Map counts, List<String> severities) {
    int total = 0
    for (String severity : severities) {
        total += (counts[severity] ?: 0) as int
    }
    return total
}
