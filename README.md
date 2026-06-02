[![Apache Sling](https://sling.apache.org/res/logos/sling.png)](https://sling.apache.org)

&#32;[![Build Status](https://ci-builds.apache.org/job/Sling/job/modules/job/sling-org-apache-sling-xss/job/master/badge/icon)](https://ci-builds.apache.org/job/Sling/job/modules/job/sling-org-apache-sling-xss/job/master/)&#32;[![Test Status](https://img.shields.io/jenkins/tests.svg?jobUrl=https://ci-builds.apache.org/job/Sling/job/modules/job/sling-org-apache-sling-xss/job/master/)](https://ci-builds.apache.org/job/Sling/job/modules/job/sling-org-apache-sling-xss/job/master/test/?width=800&height=600)&#32;[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=apache_sling-org-apache-sling-xss&metric=coverage)](https://sonarcloud.io/dashboard?id=apache_sling-org-apache-sling-xss)&#32;[![Sonarcloud Status](https://sonarcloud.io/api/project_badges/measure?project=apache_sling-org-apache-sling-xss&metric=alert_status)](https://sonarcloud.io/dashboard?id=apache_sling-org-apache-sling-xss)&#32;[![JavaDoc](https://www.javadoc.io/badge/org.apache.sling/org.apache.sling.xss.svg)](https://www.javadoc.io/doc/org.apache.sling/org.apache.sling.xss)&#32;[![Maven Central](https://maven-badges.herokuapp.com/maven-central/org.apache.sling/org.apache.sling.xss/badge.svg)](https://search.maven.org/#search%7Cga%7C1%7Cg%3A%22org.apache.sling%22%20a%3A%22org.apache.sling.xss%22) [![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

# Apache Sling XSS Protection

This module is part of the [Apache Sling](https://sling.apache.org) project.

The Apache Sling XSS Bundle provides two services for escaping and filtering XSS-prone user submitted content:

1. org.apache.sling.xss.XSSAPI
2. org.apache.sling.xss.XSSFilter

See the JavaDoc of each service for the complete API surface.

## Runtime and implementation notes

- Requires Java 11+ (the project is also built in CI with newer JDKs, including Java 25).
- Uses OSGi R7 Declarative Services.
- Uses OWASP Java Encoder and a custom AntiSamy XML policy parser.
- Uses `owasp-java-html-sanitizer` for HTML sanitization.
- Embeds ESAPI, Batik CSS, and HTML sanitizer packages as private bundle packages to avoid OSGi import conflicts.
- Includes optional invalid-href metrics integration via Sling Commons Metrics.
- Excludes legacy/conflicting transitive logging dependencies such as `commons-logging` and does not depend on Log4j 1.x.

## Build and test

```bash
# Build and package (skip tests)
mvn clean package -DskipTests

# Full build with tests
mvn clean verify

# Run all tests
mvn test

# Run a single test class
mvn test -Dtest=XSSAPIImplTest

# Run a single test method
mvn test -Dtest=XSSAPIImplTest#testGetValidHref

# Run policy parser / sanitizer regression tests
mvn test -Dtest=AntiSamyPolicyWithAdditionalGlobalAndDynamicConditionsTest

# Check / apply formatting
mvn spotless:check
mvn spotless:apply

# OSGi baseline check
mvn verify -Pbaseline

# Generate coverage report
mvn verify jacoco:report
```

## Repository layout

```text
src/
  main/
    appended-resources/
      META-INF/
    java/
      org/apache/sling/xss/          # Public API
      org/apache/sling/xss/impl/     # OSGi service implementations
      org/apache/sling/xss/impl/xml/ # AntiSamy XML policy parser
      org/apache/sling/xss/impl/style/      # CSS validation via Batik
      org/apache/sling/xss/impl/status/     # Runtime status service
      org/apache/sling/xss/impl/webconsole/ # Web console plugin
      org/owasp/html/                # Sanitizer extensions
    resources/
      ESAPI.properties
      validation.properties
      SLING-INF/
      webconsole/
  test/
    java/
      org/apache/sling/xss/impl/     # XSS API/filter/sanitizer tests
      org/apache/sling/xss/impl/xml/ # XML policy parser tests
    resources/                       # AntiSamy XML fixtures and test logging config
```
