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

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class HtmlToHtmlContentContextTest {

    private static final String INPUT = "<p>some input</p>";

    private PolicyHandler policyHandlerThrowing(boolean fallbackThrows) {
        HtmlSanitizer throwingSanitizer = mock(HtmlSanitizer.class);
        when(throwingSanitizer.scan(anyString())).thenThrow(new StackOverflowError());

        HtmlSanitizer fallbackSanitizer;
        if (fallbackThrows) {
            fallbackSanitizer = throwingSanitizer;
        } else {
            fallbackSanitizer = mock(HtmlSanitizer.class);
            when(fallbackSanitizer.scan(anyString())).thenReturn(new SanitizedResult(INPUT, 0));
        }

        PolicyHandler policyHandler = mock(PolicyHandler.class);
        when(policyHandler.getHtmlSanitizer()).thenReturn(throwingSanitizer);
        when(policyHandler.getFallbackHtmlSanitizer()).thenReturn(fallbackSanitizer);
        return policyHandler;
    }

    @Test
    public void testFallbackIsUsedOnStackOverflowError() {
        PolicyHandler policyHandler = policyHandlerThrowing(false);
        HtmlToHtmlContentContext context = new HtmlToHtmlContentContext();
        assertEquals(INPUT, context.filter(policyHandler, INPUT));
        assertTrue(context.check(policyHandler, INPUT));
    }

    /**
     * SLING - a StackOverflowError thrown by the fallback sanitizer as well must not escape into
     * application code: filter() has to fail closed with an empty string and check() with false.
     */
    @Test
    public void testSecondStackOverflowErrorFailsClosed() {
        PolicyHandler policyHandler = policyHandlerThrowing(true);
        HtmlToHtmlContentContext context = new HtmlToHtmlContentContext();
        assertEquals("", context.filter(policyHandler, INPUT));
        assertFalse(context.check(policyHandler, INPUT));
    }
}
