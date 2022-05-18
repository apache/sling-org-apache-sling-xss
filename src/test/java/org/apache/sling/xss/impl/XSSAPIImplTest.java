/*******************************************************************************
 * Licensed to the Apache Software Foundation (ASF) under one or
 * more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information regarding
 * copyright ownership. The ASF licenses this file to you under the
 * Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0 Unless required by
 * applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 ******************************************************************************/
package org.apache.sling.xss.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.regex.Pattern;

import org.apache.sling.api.resource.observation.ResourceChangeListener;
import org.apache.sling.commons.metrics.Counter;
import org.apache.sling.commons.metrics.MetricsService;
import org.apache.sling.serviceusermapping.ServiceUserMapped;
import org.apache.sling.testing.mock.sling.junit5.SlingContext;
import org.apache.sling.testing.mock.sling.junit5.SlingContextExtension;
import org.apache.sling.xss.XSSAPI;
import org.apache.sling.xss.impl.status.XSSStatusService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.osgi.framework.ServiceReference;
import org.owasp.validator.html.model.Attribute;
import org.powermock.reflect.Whitebox;

@ExtendWith(SlingContextExtension.class)
public class XSSAPIImplTest {

    private static final String RUBBISH = "rubbish";
    private static final String RUBBISH_JSON = "[\"rubbish\"]";
    private static final String RUBBISH_XML = "<rubbish/>";

    public SlingContext context = new SlingContext();

    private XSSAPI xssAPI;

    /**
     * Due to how OSGi mocks are currently designed, it's impossible to unregister services. Therefore this method has to be explicitly
     * called by each method that needs the default setup.
     *
     * The only exception currently is {@link #testGetValidHrefWithoutHrefConfig()}.
     */
    private void setUp() {
        context.registerInjectActivateService(new XSSFilterImpl());
        context.registerInjectActivateService(new XSSAPIImpl());
        xssAPI = context.getService(XSSAPI.class);
    }

    @BeforeEach
    public void before() {
        MetricsService metricsService = mock(MetricsService.class);
        when(metricsService.counter(anyString())).thenReturn(mock(Counter.class));
        context.registerService(MetricsService.class, metricsService);
        context.registerService(ServiceUserMapped.class, mock(ServiceUserMapped.class));
        context.registerService(new XSSStatusService());
    }

    @AfterEach
    public void tearDown() {
        xssAPI = null;
    }

    @ParameterizedTest
    @MethodSource("dataForEncodeToHtml")
    public void testEncodeForHTML(String source, String expected) {
        setUp();
        assertEquals(expected, xssAPI.encodeForHTML(source), "HTML Encoding '" + source + "'");
    }

    @ParameterizedTest
    @MethodSource("dataForEncodeToHtmlAttr")
    public void testEncodeForHTMLAttr(String source, String expected) {
        setUp();
        assertEquals(expected, xssAPI.encodeForHTMLAttr(source), "HTML Encoding '" + source + "'");
    }

    @ParameterizedTest
    @MethodSource("dataForEncodeToXml")
    public void testEncodeForXML(String source, String expected) {
        setUp();
        assertEquals(expected, xssAPI.encodeForXML(source), "XML Encoding '" + source + "'");
    }

    @ParameterizedTest
    @MethodSource("dataForEncodeToXmlAttr")
    public void testEncodeForXMLAttr(String source, String expected) {
        setUp();
        assertEquals(expected, xssAPI.encodeForXMLAttr(source), "XML Encoding '" + source + "'");
    }

    @ParameterizedTest
    @MethodSource("dataForFilterHtml")
    public void testFilterHTML(String source, String expected) {
        setUp();
        assertEquals(expected, xssAPI.filterHTML(source), "Filtering '" + source + "'");
    }

    private void testHref(String input, String expected) {
            String result = xssAPI.getValidHref(input);
            assertEquals(expected, result, "Requested '" +input + "'\nGot '" + result + "'\nExpected  '" + expected + "'");
    }

    @ParameterizedTest
    @MethodSource("dataForValidHref")
    public void testGetValidHref(String input, String expected) {
        setUp();
        testHref(input, expected);
    }

    @ParameterizedTest
    @MethodSource("dataForValidHref")
    public void testGetValidHrefWithoutHrefConfig(String input, String expected) {
        context.load().binaryFile("/configWithoutHref.xml", "/apps/sling/xss/configWithoutHref.xml");
        context.registerInjectActivateService(new XSSFilterImpl(), new HashMap<String, Object>(){{
            put("policyPath", "/apps/sling/xss/configWithoutHref.xml");
        }});
        context.registerInjectActivateService(new XSSAPIImpl());
        xssAPI = context.getService(XSSAPI.class);
        ServiceReference<ResourceChangeListener> xssFilterRCL = context.bundleContext().getServiceReference(ResourceChangeListener.class);
        assertEquals("/apps/sling/xss/configWithoutHref.xml", xssFilterRCL.getProperty(ResourceChangeListener.PATHS));
        // Load AntiSamy configuration without href filter
        XSSFilterImpl xssFilter = Whitebox.getInternalState(xssAPI, "xssFilter");

        Attribute hrefAttribute = Whitebox.getInternalState(xssFilter, "hrefAttribute");
        assertEquals(hrefAttribute, XSSFilterImpl.DEFAULT_HREF_ATTRIBUTE);

        // Run same tests again to check default configuration
        testHref(input, expected);
    }

    @ParameterizedTest
    @MethodSource("dataForValidInteger")
    public void testGetValidInteger(String source, String expectedAsString) {
        setUp();

        Integer expected = (expectedAsString != null) ? Integer.parseInt(expectedAsString) : null;
        assertEquals(expected, xssAPI.getValidInteger(source, 123), "Validating integer '" + source + "'");
    }

    @ParameterizedTest
    @MethodSource("dataForValidLong")
    public void testGetValidLong(String source, String expectedAsString) {
        setUp();

        Long expected = (expectedAsString != null) ? Long.parseLong(expectedAsString) : null;
        assertEquals(expected, xssAPI.getValidLong(source, 123), "Validating long '" + source + "'");
    }

    @ParameterizedTest
    @MethodSource("dataForValidDouble")
    public void testGetValidDouble(String source, String expectedAsString) {
        setUp();

        Double expected = (expectedAsString != null) ? Double.parseDouble(expectedAsString) : null;
        assertEquals(expected, xssAPI.getValidDouble(source, 123), "Validating double '" + source + "'");
    }

    @ParameterizedTest
    @MethodSource("dataForValidDimension")
    public void testGetValidDimension(String source, String expected) {
        setUp();

        assertEquals(expected, xssAPI.getValidDimension(source, "123"), "Validating dimension '" + source + "'");
    }

    @ParameterizedTest
    @MethodSource("dataForValidJSString")
    public void testEncodeForJSString(String source, String expected) {
        setUp();

        assertEquals(expected, xssAPI.encodeForJSString(source), "Encoding '" + source + "'");
    }

    @ParameterizedTest
    @MethodSource("dataForValidJSToken")
    public void testGetValidJSToken(String source, String expected) {
        setUp();

        assertEquals(expected, xssAPI.getValidJSToken(source, RUBBISH), "Validating Javascript token '" + source + "'");
    }

    @ParameterizedTest
    @MethodSource("dataForCSSString")
    public void testEncodeForCSSString(String source, String expected) {
        setUp();

        String result = xssAPI.encodeForCSSString(source);
        assertEquals(expected, result, "Encoding '" + source + "'");
    }

    @ParameterizedTest
    @MethodSource("dataForValidStyleToken")
    public void testGetValidStyleToken(String source, String expected) {
        setUp();

        String result = xssAPI.getValidStyleToken(source, RUBBISH);
        if (result == null || !result.equals(expected)) {
            fail("Validating style token '" + source + "', expecting '" + expected + "', but got '" + result + "'");
        }
    }

    @ParameterizedTest
    @MethodSource("dataForValidCSSColor")
    public void testGetValidCSSColor(String source, String expected) {
        setUp();

        String result = xssAPI.getValidCSSColor(source, RUBBISH);
        if (result == null || !result.equals(expected)) {
            fail("Validating CSS Color '" + source + "', expecting '" + expected + "', but got '" + result + "'");
        }
    }

    @ParameterizedTest
    @MethodSource("dataForValidMultilineComment")
    public void testGetValidMultiLineComment(String source, String expected) {
        setUp();

        String result = xssAPI.getValidMultiLineComment(source, RUBBISH);
        if (!result.equals(expected)) {
            fail("Validating multiline comment '" + source + "', expecting '" + expected + "', but got '" + result + "'");
        }
    }

    @ParameterizedTest
    @MethodSource("dataForValidMultilineJSON")
    public void testGetValidJSON(String source, String expected) {
        setUp();

        String result = xssAPI.getValidJSON(source, RUBBISH_JSON);
        if (!result.equals(expected)) {
            fail("Validating JSON '" + source + "', expecting '" + expected + "', but got '" + result + "'");
        }
    }

    @ParameterizedTest
    @MethodSource("dataForValidXML")
    public void testGetValidXML(String source, String expected) {
        setUp();

        String result = xssAPI.getValidXML(source, RUBBISH_XML);
        if (!result.equals(expected)) {
            fail("Validating XML '" + source + "', expecting '" + expected + "', but got '" + result + "'");
        }
    }

    @ParameterizedTest
    @ValueSource(strings= {
        "1.1.1.1",
        "255.1.1.1"
    })
    public void testRegex(String input) {
        Pattern ipPattern = Pattern.compile(XSSFilterImpl.IPv4_ADDRESS);
        assertTrue(ipPattern.matcher(input).matches());
    }

    static String[][] dataForEncodeToHtml() {
        return new String[][] {
                //         Source                            Expected Result
                //
                {null, null},
                {"simple", "simple"},

                {"<script>", "&lt;script&gt;"},
                {"<b>", "&lt;b&gt;"},

                {"günter", "günter"},
                {"\u30e9\u30c9\u30af\u30ea\u30d5\u3001\u30de\u30e9\u30bd\u30f3\u4e94\u8f2a\u4ee3\u8868\u306b1\u4e07m\u51fa\u5834\u306b\u3082\u542b\u307f", "\u30e9\u30c9\u30af\u30ea\u30d5\u3001\u30de\u30e9\u30bd\u30f3\u4e94\u8f2a\u4ee3\u8868\u306b1\u4e07m\u51fa\u5834\u306b\u3082\u542b\u307f"}
        };
    }

    static String[][] dataForEncodeToHtmlAttr() {
        return new String[][] {
                //         Source                            Expected Result
                //
                {null, null},
                {"simple", "simple"},

                {"<script>", "&lt;script>"},
                {"\" <script>alert('pwned');</script>", "&#34; &lt;script>alert(&#39;pwned&#39;);&lt;/script>"},
                {"günter", "günter"},
                {"\u30e9\u30c9\u30af\u30ea\u30d5\u3001\u30de\u30e9\u30bd\u30f3\u4e94\u8f2a\u4ee3\u8868\u306b1\u4e07m\u51fa\u5834\u306b\u3082\u542b\u307f", "\u30e9\u30c9\u30af\u30ea\u30d5\u3001\u30de\u30e9\u30bd\u30f3\u4e94\u8f2a\u4ee3\u8868\u306b1\u4e07m\u51fa\u5834\u306b\u3082\u542b\u307f"}
        };
    }

    static String[][] dataForEncodeToXml() {
        return new String[][] {
                //         Source                            Expected Result
                //
                {null, null},
                {"simple", "simple"},

                {"<script>", "&lt;script&gt;"},
                {"<b>", "&lt;b&gt;"},

                {"günter", "günter"}
        };
    }

    static String[][] dataForEncodeToXmlAttr() {
        return new String[][] {
                //         Source                            Expected Result
                //
                {null, null},
                {"simple", "simple"},

                {"<script>", "&lt;script>"},
                {"<b>", "&lt;b>"},

                {"günter", "günter"},
                {"\"xss:expression(alert('XSS'))", "&#34;xss:expression(alert(&#39;XSS&#39;))"}
        };
    }

    static String[][] dataForFilterHtml() {
        return new String[][] {
                //         Source                            Expected Result
                {null, ""},
                {"", ""},
                {"simple", "simple"},

                {"<script>ugly</script>", ""},
                {"<b>wow!</b>", "<b>wow!</b>"},

                {"<p onmouseover='ugly'>nice</p>", "<p>nice</p>"},

                {"<img src='javascript:ugly'/>", ""},
                {"<img src='nice.jpg'/>", "<img src=\"nice.jpg\" />"},

                {"<ul><li>1</li><li>2</li></ul>", "<ul><li>1</li><li>2</li></ul>"},

                {"günter", "günter"},


                {"<strike>strike</strike>", "<strike>strike</strike>"},
                {"<s>s</s>", "<s>s</s>"},

                {"<a href=\"\">empty href</a>", "<a href=\"\">empty href</a>"},
                {"<a href=\" javascript:alert(23)\">space</a>","<a>space</a>"},
                {"<table background=\"http://www.google.com\"></table>", "<table></table>"},
                // CVE-2017-14735
                {"<a href=\"javascript&colon;alert(23)\">X</a>", "<a>X</a>"},
                // CVE-2016-10006
                {"<style onload=\"alert(23)\">h1 {color:red;}</style>", "<style>h1 {\n\tcolor: red;\n}\n</style>"},
                // strip out css imports
                { "<style>@import 'foo.css';\nh1 {color:red;}</style>", "<style>h1 {\n\tcolor: red;\n}\n</style>"},
                // filter invalid tag names
                { "<style>ț1 {color:red;}\nh1 {color:green;}</style>", "<style>h1 {\n\tcolor: green;\n}\n</style>"},
                // keep valid tag names
                { "<style>h1 {color:green;}</style>", "<style>h1 {\n\tcolor: green;\n}\n</style>"},
                // filter invalid class names
                { "<style>.ș1 {color:red;}\nh1 {color:green;}</style>", "<style>h1 {\n\tcolor: green;\n}\n</style>"},
                // keep valid class names
                { "<style>*.title {color:green;}</style>", "<style>*.title {\n\tcolor: green;\n}\n</style>"},
                // filter invalid ids
                { "<style>#ă1 {color:red;}\nh1 {color:green;}</style>", "<style>h1 {\n\tcolor: green;\n}\n</style>"},
                // keep valid ids
                { "<style>#tag-1 {color:green;}</style>", "<style>*#tag-1 {\n\tcolor: green;\n}\n</style>"},
                // filter invalid pseudo-selectors
                { "<style>bar:î1 {color:red;}\nh1 {color:green;}</style>", "<style>h1 {\n\tcolor: green;\n}\n</style>"},
                // keep valid pseudo-selectors
                { "<style>bar:first-child {color:green;}</style>", "<style>bar:first-child {\n\tcolor: green;\n}\n</style>"},
                // filter invalid attributes
                { "<style>h1[data-foo=zât] {color:red;}\nh1 {color:green;}</style>", "<style>h1 {\n\tcolor: green;\n}\n</style>"}
                // keep valid attributes, unfortunately does not work
                // { "<style>h1[data-foo=bar] {color:green;}\n</style>", "<style>h1[data-foo=bar] {\n\tcolor: green;\n}\n</style>"}
        };
    }

    static String[][] dataForValidHref() {
        return new String[][] {
                //         Href                                        Expected Result
                //
                {
                    "http://localhost/?q=a+b&amp;r=1",
                    "http://localhost/?q=a+b&amp;r=1"
                },
                {
                    "/libs/wcm/core/content/sites/createlaunchwizard.html/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment?create_nested_launch=true&redirect=/sites.html/content/we-retail/language-masters/en/products/equipment#/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/biking,/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/hiking/buffalo-plaid-shorts,/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/hiking/candide-trail-short,/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/hiking/corona-shorts,/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/hiking/cuzco,/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/hiking/desert-sky-shorts,/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/hiking/fleet-fox-running-shorts,/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/hiking/hiking-pants,/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/hiking/hiking-poles,/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/hiking/rios-t-shirt,/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/hiking/slot-canyon-active-shorts,/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/hiking/stretch-fatigue-shorts,/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/hiking/trail-model-pants",
                    "/libs/wcm/core/content/sites/createlaunchwizard.html/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment?create_nested_launch=true&redirect=/sites.html/content/we-retail/language-masters/en/products/equipment#/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/biking,/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/hiking/buffalo-plaid-shorts,/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/hiking/candide-trail-short,/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/hiking/corona-shorts,/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/hiking/cuzco,/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/hiking/desert-sky-shorts,/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/hiking/fleet-fox-running-shorts,/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/hiking/hiking-pants,/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/hiking/hiking-poles,/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/hiking/rios-t-shirt,/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/hiking/slot-canyon-active-shorts,/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/hiking/stretch-fatigue-shorts,/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/hiking/trail-model-pants"
                },
                {
                    "/libs/wcm/core/content/sites/createlaunchwizard.html/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment?create_nested_launch=true&redirect=/sites.html/content/we-retail/language-masters/en/products/equipment#/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/biking,/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/hiking/buffalo-plaid-shorts,/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/hiking/candide-trail-short,/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/hiking/corona-shorts,/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/hiking/cuzco,/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/hiking/desert-sky-shorts,/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/hiking/fleet-fox-running-shorts,/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/hiking/hiking-pants,/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/hiking/hiking-poles,/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/hiking/rios-t-shirt,/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/hiking/slot-canyon-active-shorts,/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/hiking/stretch-fatigue-shorts,/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/hiking/trail-model-pants\"><script>alert(1)</script>",
                    "/libs/wcm/core/content/sites/createlaunchwizard.html/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment?create_nested_launch=true&redirect=/sites.html/content/we-retail/language-masters/en/products/equipment#/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/biking,/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/hiking/buffalo-plaid-shorts,/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/hiking/candide-trail-short,/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/hiking/corona-shorts,/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/hiking/cuzco,/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/hiking/desert-sky-shorts,/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/hiking/fleet-fox-running-shorts,/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/hiking/hiking-pants,/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/hiking/hiking-poles,/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/hiking/rios-t-shirt,/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/hiking/slot-canyon-active-shorts,/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/hiking/stretch-fatigue-shorts,/content/launches/2019/10/11/l3/content/we-retail/language-masters/en/products/equipment/hiking/trail-model-pants%22%3E%3Cscript%3Ealert(1)%3C/script%3E"
                },
                {
                        "test?discount=25%25",
                        "test?discount=25%25"
                },
                {
                        "/base?backHref=%26%23x6a%3b%26%23x61%3b%26%23x76%3b%26%23x61%3b%26%23x73%3b%26%23x63%3b%26%23x72%3b%26%23x69%3b%26%23x70%3b%26%23x74%3b%26%23x3a%3balert%281%29",
                        "/base?backHref=%26%23x6a%3b%26%23x61%3b%26%23x76%3b%26%23x61%3b%26%23x73%3b%26%23x63%3b%26%23x72%3b%26%23x69%3b%26%23x70%3b%26%23x74%3b%26%23x3a%3balert%281%29"
                },
                {
                        "%26%23x6a%3b%26%23x61%3b%26%23x76%3b%26%23x61%3b%26%23x73%3b%26%23x63%3b%26%23x72%3b%26%23x69%3b%26%23x70%3b%26%23x74%3b%26%23x3a%3balert%281%29",
                        ""
                },
                {
                        "&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3a;alert(1)",
                        ""
                },
                {"%2Fscripts%2Ftest.js", "%2Fscripts%2Ftest.js"},
                {"/etc/commerce/collections/中文", "/etc/commerce/collections/中文"},
                {"/etc/commerce/collections/\u09aa\u09b0\u09c0\u0995\u09cd\u09b7\u09be\u09ae\u09c2\u09b2\u0995", "/etc/commerce/collections/\u09aa\u09b0\u09c0\u0995\u09cd\u09b7\u09be\u09ae\u09c2\u09b2\u0995"},
                {null, ""},
                {"", ""},
                {"simple", "simple"},

                {"../parent", "../parent"},
                {"repo/günter", "repo/günter"},

                // JCR namespaces:
                {"my/page/jcr:content.feed", "my/page/jcr:content.feed"},
                {"my/jcr:content/page/jcr:content", "my/jcr:content/page/jcr:content"},
                {"my/jcr:content/encoded%20spaces", "my/jcr:content/encoded%20spaces"},
                {"my/jcr:content/this path has spaces", "my/jcr:content/this%20path%20has%20spaces"},

                {"\" onClick=ugly", "%22%20onClick=ugly"},
                {"javascript:ugly", ""},
                {"http://localhost:4502", "http://localhost:4502"},
                {"http://localhost:4502/test", "http://localhost:4502/test"},
                {"http://localhost:4502/jcr:content/test", "http://localhost:4502/jcr:content/test"},
                {"http://localhost:4502/test.html?a=b&b=c", "http://localhost:4502/test.html?a=b&b=c"},

                // space
                {"/test/ab cd", "/test/ab%20cd"},
                {"http://localhost:4502/test/ab cd", "http://localhost:4502/test/ab%20cd"},
                {"/test/ab attr=c", "/test/ab%20attr=c"},
                {"http://localhost:4502/test/ab attr=c", "http://localhost:4502/test/ab%20attr=c"},
                // "
                {"/test/ab\"cd", "/test/ab%22cd"},
                {"http://localhost:4502/test/ab\"cd", "http://localhost:4502/test/ab%22cd"},
                // '
                {"/test/ab'cd", "/test/ab%27cd"},
                {"http://localhost:4502/test/ab'cd", "http://localhost:4502/test/ab%27cd"},
                // =
                {"/test/ab=cd", "/test/ab=cd"},
                {"http://localhost:4502/test/ab=cd", "http://localhost:4502/test/ab=cd"},
                // >
                {"/test/ab>cd", "/test/ab%3Ecd"},
                {"http://localhost:4502/test/ab>cd", "http://localhost:4502/test/ab%3Ecd"},
                // <
                {"/test/ab<cd", "/test/ab%3Ccd"},
                {"http://localhost:4502/test/ab<cd", "http://localhost:4502/test/ab%3Ccd"},
                // `
                {"/test/ab`cd", "/test/ab%60cd"},
                {"http://localhost:4502/test/ab`cd", "http://localhost:4502/test/ab%60cd"},
                // colons in query string
                {"/test/search.html?0_tag:id=test", "/test/search.html?0_tag:id=test"},
                { // JCR namespaces and colons in query string
                        "/test/jcr:content/search.html?0_tag:id=test",
                        "/test/jcr:content/search.html?0_tag:id=test"
                },
                { // JCR namespaces and colons in query string plus encoded path
                        "/test%20with%20encoded%20spaces/jcr:content/search.html?0_tag:id=test",
                        "/test%20with%20encoded%20spaces/jcr:content/search.html?0_tag:id=test"
                },
                { // JCR namespaces and colons in query string plus spaces in path
                        "/test with spaces/jcr:content/search.html?0_tag:id=test",
                        "/test%20with%20spaces/jcr:content/search.html?0_tag:id=test"
                },
                { // ? in query string
                        "/test/search.html?0_tag:id=test?ing&1_tag:id=abc",
                        "/test/search.html?0_tag:id=test?ing&1_tag:id=abc",
                },
                {
                        "/test/search.html?0_tag:id=test?ing&1_tag:id=abc#fragment:test",
                        "/test/search.html?0_tag:id=test?ing&1_tag:id=abc#fragment:test",
                },
                {
                        "https://sling.apache.org/?a=1#fragment:test",
                        "https://sling.apache.org/?a=1#fragment:test"
                },
                {
                        "https://sling.apache.org/#fragment:test",
                        "https://sling.apache.org/#fragment:test"
                },
                {
                        "https://sling.apache.org/test/",
                        "https://sling.apache.org/test/"
                },
                {
                        "/content/test/",
                        "/content/test/"
                },
                { // namespace mangling + encoded parameter values
                        "/path/to/page/jcr:content/par?key=%25text",
                        "/path/to/page/jcr:content/par?key=%25text"
                },
                { // namespace mangling + incorrect escape sequence
                        "/path/to/page/jcr:content/par?key=%text",
                        ""
                },
                { // incorrect escape sequence
                        "/path/to/page/jcr:content/par?key=%text",
                        ""
                }
        };
    }

    static String[][] dataForValidInteger() {
        return new String[][] {
                //         Source                                        Expected Result
                //
                {null, "123"},
                {"100", "100"},
                {"0", "0"},

                {"junk", "123"},
                {"100.5", "123"},
                {"", "123"},
                {"null", "123"}
        };
    }

    static String[][] dataForValidLong() {
        return new String[][] {
            //         Source                                        Expected Result
            //
            {null, "123"},
            {"100", "100"},
            {"0", "0"},

            {"junk", "123"},
            {"100.5", "123"},
            {"", "123"},
            {"null", "123"}
        };
    }

    static String[][] dataForValidDouble() {
        return new String[][] {
            //         Source                                        Expected Result
            //
            {null, "123"},
            {"100.5", "100.5"},
            {"0", "0"},

            {"junk", "123"},
            {"", "123"},
            {"null", "123"}
        };
    }

    static String[][] dataForValidDimension() {
        return new String[][] {
            //         Source                                        Expected Result
            //
            {null, "123"},
            {"", "123"},
            {"100", "100"},
            {"0", "0"},

            {"junk", "123"},
            {"100.5", "123"},
            {"", "123"},
            {"null", "123"},

            {"\"auto\"", "\"auto\""},
            {"'auto'", "\"auto\""},
            {"auto", "\"auto\""},

            {"autox", "123"}
        };
    }

    static String[][] dataForValidJSString() {
        return new String[][] {
            //         Source                            Expected Result
            //
            {null, null},
            {"simple", "simple"},

            {"break\"out", "break\\x22out"},
            {"break'out", "break\\x27out"},

            {"</script>", "<\\/script>"},

            {"'alert(document.cookie)", "\\x27alert(document.cookie)"},
            {"2014-04-22T10:11:24.002+01:00", "2014\\u002D04\\u002D22T10:11:24.002+01:00"}
        };
    }

    static String[][] dataForValidJSToken() {
        return new String[][] {
            //         Source                            Expected Result
            //
            {null, RUBBISH},
            {"", RUBBISH},
            {"simple", "simple"},
            {"clickstreamcloud.thingy", "clickstreamcloud.thingy"},

            {"break out", RUBBISH},
            {"break,out", RUBBISH},

            {"\"literal string\"", "\"literal string\""},
            {"'literal string'", "'literal string'"},
            {"\"bad literal'", RUBBISH},
            {"'literal'); junk'", "'literal\\x27); junk'"},

            {"1200", "1200"},
            {"3.14", "3.14"},
            {"1,200", RUBBISH},
            {"1200 + 1", RUBBISH}
        };
    }

    static String[][] dataForCSSString() {
        return new String[][] {
            //         Source                            Expected Result
            //
            {null, null},
            {"test"   , "test"},
            {"\\"     , "\\5c"},
            {"'"      , "\\27"},
            {"\""     , "\\22"}
        };
    }

    static String[][] dataForValidStyleToken() {
        return new String[][] {
            // Source                           Expected result
            {null                               , RUBBISH},
            {""                                 , RUBBISH},

            // CSS close
            {"}"                                , RUBBISH},

            // line break
            {"br\neak"                          , RUBBISH},

            // no javascript:
            {"javascript:alert(1)"              , RUBBISH},
            {"'javascript:alert(1)'"            , RUBBISH},
            {"\"javascript:alert('XSS')\""      , RUBBISH},
            {"url(javascript:alert(1))"         , RUBBISH},
            {"url('javascript:alert(1)')"       , RUBBISH},
            {"url(\"javascript:alert('XSS')\")" , RUBBISH},

            // no expression
            {"expression(alert(1))"             , RUBBISH},
            {"expression  (alert(1))"           , RUBBISH},
            {"expression(this.location='a.co')" , RUBBISH},

            // html tags
            {"</style><script>alert(1)</script>", RUBBISH},

            // usual CSS stuff
            {"background-color"                 , "background-color"},
            {"-moz-box-sizing"                  , "-moz-box-sizing"},
            {".42%"                             , ".42%"},
            {"#fff"                             , "#fff"},

            // valid strings
            {"'literal string'"                 , "'literal string'"},
            {"\"literal string\""               , "\"literal string\""},
            {"'it\\'s here'"                    , "'it\\'s here'"},
            {"\"it\\\"s here\""                 , "\"it\\\"s here\""},

            // invalid strings
            {"\"bad string"                     , RUBBISH},
            {"'it's here'"                      , RUBBISH},
            {"\"it\"s here\""                   , RUBBISH},

            // valid parenthesis
            {"rgb(255, 255, 255)"               , "rgb(255, 255, 255)"},

            // invalid parenthesis
            {"rgb(255, 255, 255"               , RUBBISH},
            {"255, 255, 255)"                  , RUBBISH},

            // valid tokens
            {"url(http://example.com/test.png)", "url(http://example.com/test.png)"},
            {"url('image/test.png')"           , "url('image/test.png')"},

            // invalid tokens
            {"color: red"                      , RUBBISH}
        };
    }

    static String[][] dataForValidCSSColor() {
        return new String[][] {
            //      Source                          Expected Result
            //
            {null, RUBBISH},
            {"", RUBBISH},

            {"rgb(0,+0,-0)", "rgb(0,+0,-0)"},
            {"rgba ( 0\f%, 0%,\t0%,\n100%\r)", "rgba ( 0\f%, 0%,\t0%,\n100%\r)",},

            {"#ddd", "#ddd"},
            {"#eeeeee", "#eeeeee",},

            {"hsl(0,1,2)", "hsl(0,1,2)"},
            {"hsla(0,1,2,3)", "hsla(0,1,2,3)"},
            {"currentColor", "currentColor"},
            {"transparent", "transparent"},

            {"\f\r\n\t MenuText\f\r\n\t ", "MenuText"},
            {"expression(99,99,99)", RUBBISH},
            {"blue;", RUBBISH},
            {"url(99,99,99)", RUBBISH}
        };
    }

    static String[][] dataForValidMultilineComment() {
        return new String[][] {
            //Source            Expected Result
            {null               , RUBBISH},
            {"blah */ hack"     , RUBBISH},

            {"Valid comment"    , "Valid comment"}
        };
    }

    static String[][] dataForValidMultilineJSON() {
        return new String[][] {
            //Source            Expected Result
            {null,      RUBBISH_JSON},
            {"",        ""},
            {"1]",      RUBBISH_JSON},
            {"{}",      "{}"},
            {"{1}",     RUBBISH_JSON},
            {
                    "{\"test\": \"test\"}",
                    "{\"test\":\"test\"}"
            },
            {
                    "{\"test\":\"test}",
                    RUBBISH_JSON
            },
            {
                    "{\"test1\":\"test1\", \"test2\": {\"test21\": \"test21\", \"test22\": \"test22\"}}",
                    "{\"test1\":\"test1\",\"test2\":{\"test21\":\"test21\",\"test22\":\"test22\"}}"
            },
            {"[]",      "[]"},
            {"[1,2]",   "[1,2]"},
            {"[1",      RUBBISH_JSON},
            {
                    "[{\"test\": \"test\"}]",
                    "[{\"test\":\"test\"}]"
            }
        };
    }

    static String[][] dataForValidXML() {
        return new String[][] {
            //Source            Expected Result
            {null,      RUBBISH_XML},
            {"",        ""},
            {
                    "<t/>",
                    "<t/>"
            },
            {
                    "<t>",
                    RUBBISH_XML
            },
            {
                    "<t>test</t>",
                    "<t>test</t>"
            },
            {
                    "<t>test",
                    RUBBISH_XML
            },
            {
                    "<t t=\"t\">test</t>",
                    "<t t=\"t\">test</t>"
            },
            {
                    "<t t=\"t>test</t>",
                    RUBBISH_XML
            },
            {
                    "<t><w>xyz</w></t>",
                    "<t><w>xyz</w></t>"
            },
            {
                    "<t><w>xyz</t></w>",
                    RUBBISH_XML
            },
            {
                    "<?xml version=\"1.0\"?><!DOCTYPE test SYSTEM \"http://nonExistentHost:1234/\"><test/>",
                    "<?xml version=\"1.0\"?><!DOCTYPE test SYSTEM \"http://nonExistentHost:1234/\"><test/>"
            }
        };
    }
}
