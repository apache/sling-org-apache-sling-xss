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

import java.util.regex.Pattern;

public class TestInput {
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

    void runCheck(HtmlSanitizer antiSamy) throws Exception {
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