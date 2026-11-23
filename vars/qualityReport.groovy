import com.cloudbees.groovy.cps.NonCPS

/**
 * Consolidated COVERAGE & QUALITY report (E2.7): one artifact that gathers the
 * evidence this build already produced, instead of making the reader open five
 * different tabs.
 *
 * What it reads (nothing is computed again, nothing contacts the network):
 *
 *   - JaCoCo    services/<service>/build/reports/jacoco/test/jacocoTestReport.xml
 *               -> line coverage per service, and whether the service is one of
 *                  the gated ones (>= 60 % is enforced by Gradle itself);
 *   - JUnit     services/<service>/build/test-results/{test,integrationTest}/*.xml
 *               -> tests / failures / errors / skipped per service;
 *   - SonarQube sonar-quality-gate.txt  (written by sonarAnalysis)
 *               -> the status the quality gate reported;
 *   - Trivy     trivy-iac-report-<build>*.txt, trivy-image-report-<build>*.txt
 *               -> presence for THIS build plus the counts of its own summary
 *                  line (best effort: the table format is Trivy's, so an
 *                  unparseable report says so instead of guessing);
 *   - OWASP ZAP zap-summary-<build>.txt (written by zapBaselineScan)
 *               -> the per-severity totals and the PASS/WARN/BLOCK status.
 *
 * Staleness (same rule as the rest of the library: never present another
 * build's evidence as this one's):
 *
 *   - the Trivy and ZAP files are matched BY BUILD NUMBER, so a leftover of a
 *     previous build is simply not picked up;
 *   - JaCoCo and JUnit files carry no build number, so their modification time
 *     is compared with the start of this build and a file older than that is
 *     labelled as coming from a previous build instead of being summed silently.
 *
 * It is INFORMATIONAL: it never fails, never marks the build unstable and never
 * changes its result. It runs from `post { always }`, so it also reports what
 * was produced before a stage failed. The whole body is guarded, because a
 * throw inside `post { always }` would skip the cleanup steps that follow it.
 *
 * Usage:
 *   qualityReport(reportsPrefix: 'quality-report', minCoveragePercent: 60)
 *
 * Writes `<prefix>-<build>.md` and `<prefix>-<build>.html`, archives both and
 * publishes the HTML with the htmlpublisher plugin (already installed).
 */
def call(Map params = [:]) {
    String reportsPrefix = params.reportsPrefix ?: 'quality-report'
    String zapSummaryPrefix = params.zapSummaryPrefix ?: 'zap-summary'
    int minCoveragePercent = params.minCoveragePercent != null ?
            params.minCoveragePercent as int : 60
    List<String> gatedServices = (params.gatedServices ?: [
            'circleguard-auth-service', 'circleguard-identity-service',
            'circleguard-promotion-service', 'circleguard-form-service',
            'circleguard-gateway-service']).collect { it.toString() }
    String environment = params.environment ?: ''

    if (!(reportsPrefix ==~ /[A-Za-z0-9._-]+/)) {
        echo "qualityReport: '${reportsPrefix}' is not a plain file name: nothing published"
        return null
    }

    String build = env.BUILD_NUMBER ?: 'nobuild'
    String mdFile = "${reportsPrefix}-${build}.md"
    String htmlFile = "${reportsPrefix}-${build}.html"
    long buildStartedAt = 0L
    try {
        buildStartedAt = (currentBuild?.time ?: 0) as long
    } catch (Exception ignored) {
        buildStartedAt = 0L
    }

    try {
        Map evidence = collectEvidence(build, zapSummaryPrefix, buildStartedAt)
        // Explicit Map literal: Groovy binds trailing named arguments to the
        // FIRST Map parameter of a method, which here would swap `evidence` and
        // `ctx` and silently skip the whole report.
        List<Map> blocks = render(evidence,
                [build              : build,
                 branch             : env.GIT_BRANCH ?: env.BRANCH_NAME ?: 'unknown',
                 commit             : env.GIT_COMMIT ?: 'unknown',
                 environment        : environment,
                 minCoveragePercent : minCoveragePercent,
                 gatedServices      : gatedServices])

        String markdown = renderMarkdown(blocks)
        String html = renderHtml(blocks, "CircleGuard coverage & quality - build ${build}")

        writeFile file: mdFile, text: markdown
        writeFile file: htmlFile, text: html
        archiveArtifacts artifacts: "${mdFile},${htmlFile}", allowEmptyArchive: true
        // Only the report is published: with reportDir '.' publishHTML copied the whole
        // workspace (caches included, ~4.6 GB) into every build.
        String reportDir = 'quality-report-html'
        writeFile file: "${reportDir}/${htmlFile}", text: html
        publishHTML(target: [reportDir               : reportDir,
                             reportFiles             : htmlFile,
                             reportName              : 'Coverage & Quality',
                             keepAll                 : true,
                             alwaysLinkToLastBuild   : true,
                             allowMissing            : true])
        echo evidence.headline
        echo "qualityReport: ${mdFile} and ${htmlFile} archived and published"
    } catch (Exception e) {
        // Informational step: it must never break `post { always }` nor hide the
        // failure of the stage that actually matters.
        echo "qualityReport: could not be generated (${e.class.simpleName}: " +
             "${e.message}). The build result is unchanged."
    }
    return null
}

/**
 * Reads every source of the report. Returns a plain map with plain values only
 * (it crosses several `sh`/`readFile` suspension points, so no lazy JSON/XML
 * structure is ever kept here).
 */
Map collectEvidence(String build, String zapSummaryPrefix, long buildStartedAt) {
    Map evidence = [coverage: [], tests: [], sonar: null, trivy: [], zap: null,
                    stale: [], unreadable: []]

    String manifest = sh(script: manifestScript(build, zapSummaryPrefix),
                         returnStdout: true)?.toString() ?: ''
    Map<String, List<List<String>>> entries = [:]
    manifest.readLines().each { String line ->
        List<String> parts = line.split('\\|', -1) as List
        if (parts.size() >= 2 && parts[0]) {
            entries.get(parts[0], []) << parts.subList(1, parts.size())
        }
    }

    (entries['JACOCO'] ?: []).each { List<String> entry ->
        String path = entry[0]
        String service = serviceName(path)
        if (isStale(entry, buildStartedAt)) {
            evidence.stale << "${service} (JaCoCo)"
            return
        }
        Map totals = jacocoLineTotals(readFile(path))
        if (totals == null) {
            evidence.unreadable << "${service} (JaCoCo)"
            return
        }
        evidence.coverage << [service: service, missed: totals.missed as long,
                              covered: totals.covered as long]
    }
    evidence.coverage.sort { Map a, Map b -> a.service <=> b.service }

    // `?: []` because Map.get(key, default) does not store the default: without
    // it a workspace with no test results at all would throw `null + null` and
    // the whole (informational) report would be silently skipped.
    ((entries['UNIT'] ?: []) + (entries['IT'] ?: [])).each { List<String> entry ->
        String path = entry[0]
        String service = serviceName(path)
        String kind = path.split('/')[4] == 'integrationTest' ? 'integration' : 'unit'
        if (isStale(entry, buildStartedAt)) {
            evidence.stale << "${service} (${kind} tests)"
            return
        }
        Map totals = junitTotals(readFile(path))
        if (totals == null) {
            evidence.unreadable << "${service} (${kind} tests)"
            return
        }
        Map existing = evidence.tests.find {
            it.service == service && it.kind == kind
        }
        if (existing) {
            ['tests', 'failures', 'errors', 'skipped'].each { String key ->
                existing[key] = (existing[key] as long) + (totals[key] as long)
            }
        } else {
            evidence.tests << [service: service, kind: kind,
                               tests: totals.tests as long, failures: totals.failures as long,
                               errors: totals.errors as long, skipped: totals.skipped as long]
        }
    }
    evidence.tests.sort { Map a, Map b -> (a.service + a.kind) <=> (b.service + b.kind) }

    (entries['TRIVY_IAC'] ?: []).each { List<String> entry ->
        evidence.trivy << trivySummary('IaC (Terraform)', entry[0], readFile(entry[0]))
    }
    (entries['TRIVY_IMG'] ?: []).each { List<String> entry ->
        evidence.trivy << trivySummary('Imágenes Docker', entry[0], readFile(entry[0]))
    }

    (entries['ZAP_SUMMARY'] ?: []).each { List<String> entry ->
        evidence.zap = zapSummary(readFile(entry[0]), entry[0])
    }

    (entries['SONAR'] ?: []).each { List<String> entry ->
        evidence.sonar = readFile(entry[0])
    }

    return evidence
}

String manifestScript(String build, String zapSummaryPrefix) {
    // One shell call produces a `KIND|path|epoch` manifest: the workspace is
    // listed by the shell (no Pipeline Utility Steps plugin is required) and
    // every glob that matches nothing stays literal, which `emit` rejects with
    // a plain `[ -f ]`. `set +x` keeps the (long) list out of the build log.
    // The build number is interpolated only where the file name carries it, so
    // the reports of a previous build can never be picked up.
    return 'set +x\n' +
        'emit() {\n' +
        '  if [ -f "$1" ]; then\n' +
        '    echo "$2|$1|$(stat -c %Y "$1" 2>/dev/null || echo 0)"\n' +
        '  fi\n' +
        '}\n' +
        'for f in services/*/build/reports/jacoco/test/jacocoTestReport.xml; do emit "$f" JACOCO; done\n' +
        'for f in services/*/build/test-results/test/*.xml; do emit "$f" UNIT; done\n' +
        'for f in services/*/build/test-results/integrationTest/*.xml; do emit "$f" IT; done\n' +
        'for f in trivy-iac-report-' + build + '*.txt; do emit "$f" TRIVY_IAC; done\n' +
        'for f in trivy-image-report-' + build + '*.txt; do emit "$f" TRIVY_IMG; done\n' +
        'for f in ' + zapSummaryPrefix + '-' + build + '.txt; do emit "$f" ZAP_SUMMARY; done\n' +
        'if [ -f sonar-quality-gate.txt ]; then emit sonar-quality-gate.txt SONAR; fi\n'
}

/** `services/<service>/...` -> `<service>`; anything else keeps its first segment. */
String serviceName(String path) {
    List<String> parts = (path ?: '').split('/') as List
    return parts.size() > 1 ? parts[1] : (path ?: 'unknown')
}

/**
 * A file older than the start of this build belongs to a previous run (JaCoCo
 * and JUnit names carry no build number). An unknown timestamp (epoch 0 or a
 * non numeric one) is NOT treated as stale: refusing to show data we cannot
 * date would be worse than showing it with its own timestamp in the report.
 */
boolean isStale(List<String> entry, long buildStartedAt) {
    if (buildStartedAt <= 0 || entry.size() < 2) {
        return false
    }
    long modified
    try {
        modified = Long.parseLong(entry[1]) * 1000L
    } catch (NumberFormatException ignored) {
        return false
    }
    return modified > 0 && modified < buildStartedAt
}

String timestampOf(List<String> entry) {
    if (entry.size() < 2) {
        return 'unknown'
    }
    long seconds
    try {
        seconds = Long.parseLong(entry[1])
    } catch (NumberFormatException ignored) {
        return 'unknown'
    }
    if (seconds <= 0) {
        return 'unknown'
    }
    try {
        return java.time.Instant.ofEpochSecond(seconds)
                .atZone(java.time.ZoneId.systemDefault()).toLocalDateTime().toString()
    } catch (Exception ignored) {
        return 'unknown'
    }
}

/**
 * Root-level LINE counters of a JaCoCo report. The XML is walked with a depth
 * counter instead of XmlSlurper on purpose: `groovy.util.XmlSlurper` does not
 * exist in every Groovy version a Shared Library has to run on, while this
 * tokeniser only depends on the (stable) structure JaCoCo emits — `<package>`
 * opens a level, `</package>` closes it, and only counters OUTSIDE a package
 * belong to the report total.
 */
@NonCPS
Map jacocoLineTotals(String xml) {
    if (!xml || !xml.contains('<report')) {
        return null
    }
    java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(
            '<package(?=[\\s>])|</package\\s*>|<counter\\b[^>]*>')
    java.util.regex.Matcher matcher = pattern.matcher(xml)
    int depth = 0
    long missed = -1
    long covered = -1
    while (matcher.find()) {
        String token = matcher.group()
        if (token.startsWith('<package')) {
            depth++
        } else if (token.startsWith('</package')) {
            depth = depth > 0 ? depth - 1 : 0
        } else if (depth == 0 && xmlAttr(token, 'type') == 'LINE') {
            try {
                missed = Long.parseLong(xmlAttr(token, 'missed') ?: '-1')
                covered = Long.parseLong(xmlAttr(token, 'covered') ?: '-1')
            } catch (NumberFormatException ignored) {
                return null
            }
        }
    }
    if (missed < 0 || covered < 0) {
        return null
    }
    return [missed: missed, covered: covered]
}

/** Sums every `<testsuite>` element (Gradle writes one root, JUnit5 tools many). */
@NonCPS
Map junitTotals(String xml) {
    if (!xml || !xml.contains('testsuite')) {
        return null
    }
    java.util.regex.Pattern pattern = java.util.regex.Pattern.compile('<testsuite\\b[^>]*>')
    java.util.regex.Matcher matcher = pattern.matcher(xml)
    long tests = 0
    long failures = 0
    long errors = 0
    long skipped = 0
    boolean found = false
    while (matcher.find()) {
        String tag = matcher.group()
        found = true
        tests += longAttr(tag, 'tests')
        failures += longAttr(tag, 'failures')
        errors += longAttr(tag, 'errors')
        skipped += longAttr(tag, 'skipped')
    }
    return found ? [tests: tests, failures: failures, errors: errors, skipped: skipped] : null
}

@NonCPS
long longAttr(String tag, String name) {
    String value = xmlAttr(tag, name)
    if (value == null) {
        return 0L
    }
    try {
        return Long.parseLong(value)
    } catch (NumberFormatException ignored) {
        return 0L
    }
}

@NonCPS
String xmlAttr(String tag, String name) {
    java.util.regex.Matcher matcher = java.util.regex.Pattern
            .compile('(?:^|\\s)' + name + '="([^"]*)"').matcher(tag)
    return matcher.find() ? matcher.group(1) : null
}

/**
 * Severity counts out of the OWN summary of a Trivy report (the line that says
 * `Total: ...`, plus the two lines that follow it, because the table splits the
 * counts over rows). Nothing is guessed: when no such line exists the report is
 * reported as "not interpretable" and the reader is pointed at the artifact.
 */
@NonCPS
Map trivySummary(String scope, String path, String text) {
    Map result = [scope: scope, path: path, counts: null]
    if (!text) {
        return result
    }
    List<String> lines = text.readLines()
    int start = -1
    for (int i = lines.size() - 1; i >= 0; i--) {
        if ((lines[i] =~ /(?i)\btotal\s*:/).find()) {
            start = i
            break
        }
    }
    if (start < 0) {
        return result
    }
    String window = lines.subList(start, Math.min(start + 3, lines.size())).join(' ')
    Map<String, Integer> counts = [:]
    java.util.regex.Matcher matcher = java.util.regex.Pattern
            .compile('(?i)\\b(CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN)\\s*:\\s*(\\d+)')
            .matcher(window)
    while (matcher.find()) {
        String severity = matcher.group(1).toUpperCase()
        int value = matcher.group(2) as int
        if (counts[severity] == null || value > counts[severity]) {
            counts[severity] = value
        }
    }
    result.counts = counts.isEmpty() ? null : counts
    return result
}

/**
 * Reads the summary written by `zapBaselineScan` (our own format, so it is
 * stable): the `status:` and `totals:` lines are all this report needs.
 */
@NonCPS
Map zapSummary(String text, String path) {
    Map result = [path: path, status: 'unknown', counts: null, findings: '']
    if (!text) {
        return result
    }
    text.eachLine { String line ->
        String trimmed = line.trim()
        if (trimmed.startsWith('status:')) {
            result.status = trimmed.substring('status:'.length()).trim()
        } else if (trimmed.startsWith('totals:')) {
            Map<String, Integer> counts = [:]
            java.util.regex.Matcher matcher = java.util.regex.Pattern
                    .compile('(Informational|Low|Medium|High|Critical):\\s*(\\d+)')
                    .matcher(trimmed)
            while (matcher.find()) {
                counts[matcher.group(1)] = matcher.group(2) as int
            }
            if (!counts.isEmpty()) {
                result.counts = counts
            }
        } else if (trimmed.startsWith('findings:')) {
            result.findings = trimmed.substring('findings:'.length()).trim()
        }
    }
    return result
}

/** Builds the ordered list of blocks shared by the Markdown and HTML renderers. */
List<Map> render(Map evidence, Map ctx) {
    List<Map> blocks = []
    int min = ctx.minCoveragePercent as int

    blocks << [type: 'h1', text: 'Informe consolidado de cobertura y calidad']
    String header = "build ${ctx.build} · branch ${ctx.branch} · commit ${ctx.commit}"
    if (ctx.environment) {
        header += " · environment ${ctx.environment}"
    }
    blocks << [type: 'p', text: header + ' · generado ' + java.time.Instant.now()]
    blocks << [type: 'p',
               text: 'Reporte informativo: consolida la evidencia que este build ya ' +
                     'produjo (JaCoCo, JUnit, SonarQube, Trivy y OWASP ZAP). No cambia ' +
                     'el resultado del build.']

    // ---------------------------------------------------------- coverage
    blocks << [type: 'h2', text: '1. Cobertura de líneas (JaCoCo)']
    if (evidence.coverage.isEmpty()) {
        blocks << [type: 'p', text: 'Sin informes de cobertura en este build ' +
                                    '(la etapa Tests no llegó a generarlos).']
    } else {
        List<List<String>> rows = []
        long totalMissed = 0
        long totalCovered = 0
        evidence.coverage.each { Map entry ->
            long missed = entry.missed as long
            long covered = entry.covered as long
            totalMissed += missed
            totalCovered += covered
            long total = missed + covered
            int percent = total > 0 ? (int) Math.round(covered * 100.0d / total) : 0
            boolean gated = entry.service in ctx.gatedServices
            String state
            if (!gated) {
                state = 'sin gate'
            } else if (percent >= min) {
                state = "OK (gate >= ${min} %)"
            } else {
                state = "BAJO (gate >= ${min} %)"
            }
            rows << [entry.service, covered.toString(), total.toString(),
                     "${percent} %", state]
        }
        long grandTotal = totalMissed + totalCovered
        int overall = grandTotal > 0 ? (int) Math.round(totalCovered * 100.0d / grandTotal) : 0
        blocks << [type: 'table',
                   headers: ['Servicio', 'Líneas cubiertas', 'Líneas totales',
                             'Cobertura', 'Estado'],
                   rows   : rows]
        blocks << [type: 'p',
                   text: "Total del monorepo: ${totalCovered} de ${grandTotal} líneas " +
                         "(${overall} %). El gate de Gradle (>= ${min} %) se aplica en " +
                         'ejecución sobre los servicios núcleo; este informe solo lo refleja.']
    }

    // -------------------------------------------------------------- tests
    blocks << [type: 'h2', text: '2. Pruebas automatizadas']
    if (evidence.tests.isEmpty()) {
        blocks << [type: 'p', text: 'Sin resultados de pruebas en este build.']
    } else {
        List<List<String>> rows = evidence.tests.collect { Map entry ->
            [entry.service, entry.kind, entry.tests.toString(), entry.failures.toString(),
             entry.errors.toString(), entry.skipped.toString()]
        }
        long totalTests = evidence.tests.sum { it.tests as long } as long
        long totalFailures = evidence.tests.sum { it.failures as long } as long
        long totalErrors = evidence.tests.sum { it.errors as long } as long
        long totalSkipped = evidence.tests.sum { it.skipped as long } as long
        blocks << [type: 'table',
                   headers: ['Servicio', 'Tipo', 'Tests', 'Fallas', 'Errores', 'Omitidos'],
                   rows   : rows]
        blocks << [type: 'p',
                   text: "Total: ${totalTests} tests, ${totalFailures} fallas, " +
                         "${totalErrors} errores, ${totalSkipped} omitidos."]
    }

    // ------------------------------------------------------------- sonar
    blocks << [type: 'h2', text: '3. Análisis estático (SonarQube)']
    String sonarStatus = sonarStatus(evidence.sonar)
    blocks << [type: 'p', text: 'Quality gate: ' + sonarStatus +
                                (evidence.sonar ? '' : ' (no se ejecutó en este build: ' +
                                                       'sonar: false o la etapa no corrió).')]

    // ---------------------------------------------------------- security
    blocks << [type: 'h2', text: '4. Seguridad']
    if (evidence.trivy.isEmpty() && evidence.zap == null) {
        blocks << [type: 'p', text: 'Sin escaneos de seguridad en este build ' +
                                    '(trivyScan / trivyImageScan / zapScan están ' +
                                    'opt-in y desactivados por defecto).']
    } else {
        List<List<String>> rows = []
        evidence.trivy.each { Map entry ->
            String findings = entry.counts ?
                    entry.counts.collect { String k, Object v -> "${k}: ${v}" }.join(', ') :
                    'resumen no interpretable (ver el artefacto)'
            rows << ['Trivy ' + entry.scope, entry.path, findings]
        }
        if (evidence.zap) {
            String zapFindings = evidence.zap.counts ?
                    evidence.zap.counts.collect { String k, Object v -> "${k}: ${v}" }.join(', ') :
                    (evidence.zap.findings ?: 'sin desglose')
            rows << ['OWASP ZAP baseline', evidence.zap.path,
                     "${zapFindings} · estado ${evidence.zap.status}"]
        }
        blocks << [type: 'table', headers: ['Herramienta', 'Evidencia', 'Resultado'],
                   rows   : rows]
        blocks << [type: 'p',
                   text: 'Los informes completos de Trivy y de ZAP se archivan con el ' +
                         'build; este listado es solo su resumen.']
    }

    // ------------------------------------------------------ limitations
    blocks << [type: 'h2', text: '5. Limitaciones declaradas']
    blocks << [type: 'p',
               text: 'ZAP Baseline es pasivo (spider + reglas pasivas): no ejecuta ' +
                     'ataques, no detecta inyecciones ni XSS activo, el spider ' +
                     'tradicional no ejecuta JavaScript (las llamadas XHR de la SPA ' +
                     'requieren -j) y, sin OpenAPI, los endpoints POST no se ' +
                     'rastrean. Los endpoints protegidos responden 401 y su ' +
                     'superficie queda fuera de este escaneo. ZAP no tiene ' +
                     'severidad Critical (su máximo es High).']
    if (evidence.stale) {
        blocks << [type: 'p',
                   text: 'Evidencia de una build anterior, excluida del consolidado: ' +
                         evidence.stale.sort().join(', ') + '.']
    }
    if (evidence.unreadable) {
        blocks << [type: 'p',
                   text: 'Archivos presentes pero no interpretables: ' +
                         evidence.unreadable.sort().join(', ') + '.']
    }
    return blocks
}

@NonCPS
String sonarStatus(String raw) {
    if (!raw) {
        return 'no disponible'
    }
    java.util.regex.Matcher matcher = java.util.regex.Pattern
            .compile('(?m)^status\\s*=\\s*(\\S+)').matcher(raw)
    if (matcher.find()) {
        return matcher.group(1)
    }
    String first = raw.readLines().find { it?.trim() }
    return first ? first.trim() : 'no disponible'
}

String renderMarkdown(List<Map> blocks) {
    StringBuilder sb = new StringBuilder()
    blocks.each { Map block ->
        switch (block.type) {
            case 'h1':
                sb << '# ' + block.text + '\n\n'
                break
            case 'h2':
                sb << '## ' + block.text + '\n\n'
                break
            case 'p':
                sb << block.text + '\n\n'
                break
            case 'table':
                sb << '| ' + block.headers.join(' | ') + ' |\n'
                sb << '|' + block.headers.collect { '---' }.join('|') + '|\n'
                block.rows.each { List<String> row ->
                    sb << '| ' + row.collect { mdCell(it) }.join(' | ') + ' |\n'
                }
                sb << '\n'
                break
            default:
                break
        }
    }
    return sb.toString()
}

String renderHtml(List<Map> blocks, String title) {
    StringBuilder sb = new StringBuilder()
    sb << '<!DOCTYPE html>\n<html lang="es">\n<head>\n<meta charset="utf-8"/>\n'
    sb << '<title>' + htmlEscape(title) + '</title>\n'
    sb << '<style>\n' +
        'body{font-family:system-ui,Segoe UI,Roboto,sans-serif;margin:2rem;color:#111}\n' +
        'table{border-collapse:collapse;margin:.5rem 0 1.5rem;width:100%}\n' +
        'th,td{border:1px solid #d0d0d0;padding:.4rem .6rem;text-align:left;' +
        'font-size:.9rem}\n' +
        'th{background:#f3f4f6}\n' +
        'h1{font-size:1.4rem}h2{font-size:1.1rem;margin-top:1.8rem}\n' +
        'p{max-width:70ch;line-height:1.5}\n' +
        '</style>\n</head>\n<body>\n'
    blocks.each { Map block ->
        switch (block.type) {
            case 'h1':
                sb << '<h1>' + htmlEscape(block.text) + '</h1>\n'
                break
            case 'h2':
                sb << '<h2>' + htmlEscape(block.text) + '</h2>\n'
                break
            case 'p':
                sb << '<p>' + htmlEscape(block.text) + '</p>\n'
                break
            case 'table':
                sb << '<table><thead><tr>'
                block.headers.each { String h -> sb << '<th>' + htmlEscape(h) + '</th>' }
                sb << '</tr></thead><tbody>'
                block.rows.each { List<String> row ->
                    sb << '<tr>'
                    row.each { String cell -> sb << '<td>' + htmlEscape(cell) + '</td>' }
                    sb << '</tr>'
                }
                sb << '</tbody></table>\n'
                break
            default:
                break
        }
    }
    sb << '</body>\n</html>\n'
    return sb.toString()
}

@NonCPS
String mdCell(Object value) {
    String text = (value ?: '').toString()
    return text.replace('|', '\\|').replace('\n', ' ')
}

@NonCPS
String htmlEscape(Object value) {
    return (value ?: '').toString()
            .replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            .replace('"', '&quot;')
}
