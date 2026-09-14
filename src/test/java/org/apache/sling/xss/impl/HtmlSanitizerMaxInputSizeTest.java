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

import org.apache.commons.lang3.StringUtils;
import org.apache.sling.xss.impl.xml.AntiSamyPolicy;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies that the {@code maxInputSize} directive from the policy file is actually enforced: the
 * embedded policy declares a limit of 200000 characters and inputs above it must be rejected
 * (fail-closed) instead of being processed.
 */
public class HtmlSanitizerMaxInputSizeTest {

    public static final String POLICY_FILE = "SLING-INF/content/config.xml";

    // must match the maxInputSize directive of the embedded policy file
    private static final int EMBEDDED_POLICY_MAX_INPUT_SIZE = 200000;

    private static HtmlSanitizer antiSamy;

    @BeforeAll
    public static void setup() throws InvalidConfigException, XMLStreamException, IOException {
        antiSamy = new HtmlSanitizer(new AntiSamyPolicy(
                HtmlSanitizerMaxInputSizeTest.class.getClassLoader().getResourceAsStream(POLICY_FILE)));
    }

    @Test
    public void testInputBelowMaxInputSizeIsProcessed() {
        String input = "<p>" + StringUtils.repeat('a', 1000) + "</p>";
        SanitizedResult result = antiSamy.scan(input);
        assertEquals(0, result.getNumberOfErrors());
        assertTrue(result.getSanitizedString().contains(StringUtils.repeat('a', 1000)));
    }

    @Test
    public void testOversizedInputIsRejected() {
        String input = "<p>" + StringUtils.repeat('a', EMBEDDED_POLICY_MAX_INPUT_SIZE) + "</p>";
        SanitizedResult result = antiSamy.scan(input);
        assertTrue(result.getNumberOfErrors() > 0, "Expected an error for an input exceeding maxInputSize.");
        assertTrue(
                StringUtils.isEmpty(result.getSanitizedString()),
                "Expected empty filtered output for an input exceeding maxInputSize.");
    }
}
