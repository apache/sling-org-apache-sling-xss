# Project Overview

OSGi bundle providing XSS protection for Apache Sling. Exposes `XSSAPI` and `XSSFilter` services backed by OWASP AntiSamy (via a custom XML policy parser), OWASP Java Encoder, and `owasp-java-html-sanitizer`. The bundle embeds ESAPI, Batik CSS, and HTML sanitizer packages as private bundle packages (see `bnd.bnd`) to avoid OSGi import conflicts. It also provides optional invalid-href metrics integration via Sling Commons Metrics. Requires Java 11+ (and is CI-tested with newer JDKs, including Java 25).

# Core Commands

```bash
# Build and package (skips tests)
mvn clean package -DskipTests

# Full build with tests
mvn clean verify

# Run all tests
mvn test

# Run a single test class
mvn test -Dtest=XSSAPIImplTest

# Run a single test method
mvn test -Dtest=XSSAPIImplTest#testGetValidHref

# Run policy parser/sanitizer regression tests
mvn test -Dtest=AntiSamyPolicyWithAdditionalGlobalAndDynamicConditionsTest

# Apply Spotless formatting (inherited from sling-bundle-parent)
mvn spotless:apply

# Check formatting without applying
mvn spotless:check

# OSGi baseline check
mvn verify -Pbaseline

# Generate coverage report
mvn verify jacoco:report
```

# Project Layout

```
src/
  main/
    appended-resources/
      META-INF/
        LICENSE
        NOTICE
    java/
      org/apache/sling/xss/          # Public API: XSSAPI, XSSFilter, ProtectionContext
      org/apache/sling/xss/impl/     # OSGi service implementations (XSSAPIImpl, XSSFilterImpl, HtmlSanitizer, XSSMetricsService…)
      org/apache/sling/xss/impl/xml/ # Custom AntiSamy XML policy parser (Jackson-based)
      org/apache/sling/xss/impl/style/ # CSS validation via Batik
      org/apache/sling/xss/impl/status/ # Web console status service
      org/apache/sling/xss/impl/webconsole/ # Felix web console plugin
      org/owasp/html/                # DynamicAttributesSanitizerPolicy (extends owasp sanitizer)
    resources/
      ESAPI.properties               # ESAPI config (excluded from RAT)
      validation.properties          # ESAPI validation rules (excluded from RAT)
      SLING-INF/                     # Sling resource definitions
      webconsole/                    # Web console static assets
  test/
    java/org/apache/sling/xss/impl/ # JUnit 5 tests for XSS API/filter/sanitizer behavior
    java/org/apache/sling/xss/impl/xml/ # XML policy parser tests
    resources/                       # AntiSamy XML config fixtures used by tests
bnd.bnd                              # OSGi bundle manifest overrides (private package embedding)
pom.xml
```

# Development Patterns & Constraints

- **Java 11**, OSGi R7, OSGi Declarative Services (DS) annotations from `org.osgi.service.component.annotations`.
- Do **not** use Felix SCR annotations (`org.apache.felix.scr.annotations`).
- All impl classes are in `org.apache.sling.xss.impl` and must stay in the `Private-Package` declared in `bnd.bnd`.
- Public API (`org.apache.sling.xss`) is versioned via `@Version` in `package-info.java`; increment according to OSGi semantic versioning when changing interfaces.
- ESAPI, Batik, and owasp-html-sanitizer are embedded via `bnd.bnd` private packages — do not add OSGi `Import-Package` for them.
- Invalid href metrics are emitted via `XSSMetricsService` and `org.apache.sling.commons.metrics` when a `MetricsService` is available (optional dynamic DS reference).
- In the web console plugin, always HTML-escape request-derived values (for example `consoleRoot`) before interpolating into markup (`StringEscapeUtils.escapeHtml4`).
- Formatting is enforced by Spotless (inherited from `sling-bundle-parent`). Run `mvn spotless:apply` before committing.
- 4-space indentation, no wildcard imports in non-generated code.
- License header required on every source file (enforced by Apache RAT).

# Git Workflow

- Branch names follow the Jira issue key: `SLING-XXXXX` or `maia/workflow-<id>`.
- Commit messages: `SLING-XXXXX: <short description>` for Jira-tracked work; `chore(deps): …` for dependency bumps.
- PRs target `master`. CI runs via Jenkins (`Jenkinsfile`) and GitHub Actions.
- Do not `git push` to remote in agent workflows.

# Testing Guidelines

- Framework: JUnit 5 (`junit-jupiter` 5.8.2) + Mockito 4 + Sling Mock (`sling-mock.junit5`).
- Test files live in `src/test/java/org/apache/sling/xss/impl/`.
- XML parser tests live in `src/test/java/org/apache/sling/xss/impl/xml/`.
- AntiSamy XML policy fixtures live in `src/test/resources/` (e.g., `configWithoutHref.xml`, `configWithAdditionalGlobalAndDynamicConditions.xml`, `configWithoutDifferentCaseDuplicateLiterals.xml`).
- JaCoCo coverage is scoped to `org/apache/sling/xss/**` only (excludes embedded third-party classes).
- Run coverage: `mvn verify` then open `target/site/jacoco/index.html`.

# Gotchas

- ESAPI classes are embedded (unpacked from the ESAPI jar during `prepare-package`). Changes to the ESAPI version may require updating `bnd.bnd` private-package exclusions.
- `commons-logging`, `commons-collections`, `commons-lang`, and `xml-apis` are explicitly excluded from ESAPI/Batik transitive deps to avoid OSGi conflicts — do not re-introduce them.
- The `sling-org-apache-sling-xss` artifact itself is excluded from `sling-mock.junit5` in test scope to prevent stale OSGi metadata from older releases interfering with tests.
- `ESAPI.properties` and `validation.properties` lack Apache license headers by design; they are RAT-excluded in `pom.xml`.
- `AntiSamyPolicyAdapter` intentionally uses `sun.misc.Unsafe` plus a Java 22+ fallback path to clear html-sanitizer attribute guards across JDK versions; avoid refactoring this blindly.
- OSGi baseline comparison runs against the last released artifact. A binary-incompatible change without a version bump will fail `mvn verify -Pbaseline`.

# Security

<!-- sling-security-default:start -->
The threat model for this project is https://github.com/apache/sling/blob/master/docs/threat-model.md .
<!-- sling-security-default:end -->
