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

import javax.xml.stream.XMLStreamException;

import java.io.IOException;

import org.apache.sling.xss.impl.xml.AntiSamyPolicy;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

public class AntiSamyPolicyWithAdditionalGlobalAndDynamicConditionsTest {

    public static final String POLICY_FILE = "./configWithAdditionalGlobalAndDynamicConditions.xml";
    private static HtmlSanitizer antiSamy;

    @BeforeAll
    public static void setup() throws InvalidConfigException, XMLStreamException, IOException {
        antiSamy = new HtmlSanitizer(new AntiSamyPolicy(AntiSamyPolicyWithAdditionalGlobalAndDynamicConditionsTest.class
                .getClassLoader()
                .getResourceAsStream(POLICY_FILE)));
    }

    @ParameterizedTest
    @MethodSource("dataForDynamicAttributes")
    public void testDynamicAttributes(TestInput testInput) throws Exception {
        testInput.skipComparingInputWithOutput = false;
        testInput.runCheck(antiSamy);
    }

    @ParameterizedTest
    @MethodSource("dataForGlobalAttributes")
    public void testGlobalAttributes(TestInput testInput) throws Exception {
        testInput.skipComparingInputWithOutput = false;
        testInput.runCheck(antiSamy);
    }

    static TestInput[] dataForGlobalAttributes() {
        return new TestInput[] {
            new TestInput("<p draggable=\"wrong\">This is a paragraph.</p>", "<p", false),
            new TestInput("<p draggable=\"auto\">This is a paragraph.</p>", "<p", true),
            new TestInput("<p draggable=\"true\">This is a draggable paragraph.</p>", "<p", true),
            new TestInput("<p contenteditable=\"wrong\">This is a paragraph.</p>", "<p", false),
            new TestInput("<p contenteditable=\"true\">This is a paragraph.</p>", "<p", true),
        };
    }

    static TestInput[] dataForDynamicAttributes() {
        return new TestInput[] {
            new TestInput(
                    "<p data-test=\"test-purpose\">This is a paragraph.</p>",
                    "<p data-test=\"test-purpose\">This is a paragraph.</p>",
                    true),
            new TestInput(
                    "<p data-test=\"test\">This is a paragraph.</p>",
                    "<p data-test=\"test\">This is a paragraph.</p>",
                    true),
        };
    }
}
