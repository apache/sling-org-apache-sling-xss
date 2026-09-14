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
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The CSS violation count that {@link org.apache.sling.xss.impl.style.CssValidator} tracks for a scan is
 * held in a {@code ThreadLocal} and reset at the start of every {@link HtmlSanitizer#scan(String)} call.
 * Verifies that this reset actually happens on every scan, so that a violation recorded while scanning
 * one input on a thread does not leak into the result of the next scan on that same, reused thread.
 */
public class HtmlSanitizerCssViolationCleanupTest {

    public static final String POLICY_FILE = "SLING-INF/content/config.xml";

    private static HtmlSanitizer antiSamy;

    @BeforeAll
    public static void setup() throws InvalidConfigException, XMLStreamException, IOException {
        antiSamy = new HtmlSanitizer(new AntiSamyPolicy(
                HtmlSanitizerCssViolationCleanupTest.class.getClassLoader().getResourceAsStream(POLICY_FILE)));
    }

    @Test
    public void testCssViolationFromPreviousScanDoesNotLeakIntoNextScanOnSameThread() {
        SanitizedResult withViolation = antiSamy.scan("<p style=\"behavior:url(#default#userData)\">hi</p>");
        assertTrue(
                withViolation.getNumberOfErrors() > 0,
                "Expected the disallowed 'behavior' CSS property to be reported as an error.");

        SanitizedResult clean = antiSamy.scan("<p style=\"color:red\">hi</p>");
        assertEquals(
                0,
                clean.getNumberOfErrors(),
                "The CSS violation from the previous scan on this thread must not carry over into this scan.");
    }
}
