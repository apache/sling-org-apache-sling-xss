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

import org.apache.sling.xss.impl.xml.AntiSamyPolicy;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

public class AntiSamyPolicyWithTestConfigTest {

    public static final String POLICY_FILE = "./testConfig.xml";
    private static HtmlSanitizer antiSamy;

    @BeforeAll
    public static void setup() throws InvalidConfigException, XMLStreamException, IOException {
        antiSamy = new HtmlSanitizer(new AntiSamyPolicy(AntiSamyPolicyWithTestConfigTest.class.getClassLoader().getResourceAsStream(POLICY_FILE)));
    }

    @ParameterizedTest
    @MethodSource("dataForDynamicAttributes")
    public void testDynamicAttributes(TestInput testInput) throws Exception {
         testInput.skipComparingInputWithOutput = false;
         testInput.runCheck();
    }

    @ParameterizedTest
    @MethodSource("dataForGlobalAttributes")
    public void testGlobalAttributes(TestInput testInput) throws Exception {
         testInput.skipComparingInputWithOutput = false;
         testInput.runCheck();
    }


    static TestInput[] dataForGlobalAttributes() {
        return new TestInput[]{
                new TestInput("<p draggable=\"wrong\">This is a paragraph.</p>",
                        "<p",false),
                new TestInput("<p draggable=\"auto\">This is a paragraph.</p>",
                        "<p", true),
                new TestInput("<p draggable=\"true\">This is a draggable paragraph.</p>",
                        "<p", true),
                new TestInput("<p contenteditable=\"wrong\">This is a paragraph.</p>",
                        "<p",false),
                new TestInput("<p contenteditable=\"true\">This is a paragraph.</p>",
                        "<p", true),
        };
    }

     static TestInput[] dataForDynamicAttributes() {
        return new TestInput[]{
                new TestInput("<p data-test=\"test-purpose\">This is a paragraph.</p>",
                       "<p data-test=\"test-purpose\">This is a paragraph.</p>", true),
                new TestInput("<p data-test=\"test\">This is a paragraph.</p>",
                       "<p data-test=\"test\">This is a paragraph.</p>", true),
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
 
        void runCheck() throws Exception {
            String cleanHTML = antiSamy.scan(input).getSanitizedString();
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
                                            pattern.matcher(antiSamy.scan(input).getSanitizedString()).find(),
                                            String.format("Expected that filtered output '%s' for input '%s' would partialy match to following pattern: '%s'.",
                                                            cleanHTML,
                                                            input,
                                                            expectedPartialOutput));
                    } else {
                            assertTrue(
                                            antiSamy.scan(input).getSanitizedString().contains(expectedPartialOutput),
                                            String.format("Expected that filtered output '%s' for input '%s' would contain '%s'.",
                                                            cleanHTML,
                                                            input,
                                                            expectedPartialOutput));
                    }
            } else {
                    if (pattern != null) {
                            assertFalse(pattern.matcher(antiSamy.scan(input).getSanitizedString()).find(),
                                            String.format("Expected that filtered output '%s' for input '%s', would NOT partialy match to following pattern:: '%s'.",
                                                            cleanHTML,
                                                            input, expectedPartialOutput));
                    } else {
                            assertFalse(antiSamy.scan(input).getSanitizedString().contains(expectedPartialOutput),
                                            String.format("Expected that filtered output '%s' for input '%s', would NOT contain '%s'.",
                                                            cleanHTML,
                                                            input, expectedPartialOutput));
                    }
            }
        }
    }
}