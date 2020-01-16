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

import org.apache.sling.commons.metrics.Counter;
import org.apache.sling.commons.metrics.MetricsService;
import org.apache.sling.serviceusermapping.ServiceUserMapped;
import org.apache.sling.testing.mock.sling.junit.SlingContext;
import org.apache.sling.xss.XSSFilter;
import org.apache.sling.xss.impl.status.XSSStatusService;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class XSSFilterImplTest {

    @Rule
    public SlingContext context = new SlingContext();

    private XSSFilter xssFilter;

    @After
    public void tearDown() {
        xssFilter = null;
    }

    @Before
    public void setUp() {
        MetricsService metricsService = mock(MetricsService.class);
        when(metricsService.counter(anyString())).thenReturn(mock(Counter.class));
        context.registerService(MetricsService.class, metricsService);
        context.registerService(ServiceUserMapped.class, mock(ServiceUserMapped.class));
        context.registerService(new XSSStatusService());
    }

    @Test
    public void testResourceBasedPolicy() {
        context.load().binaryFile(this.getClass().getClassLoader().getResourceAsStream(XSSFilterImpl.EMBEDDED_POLICY_PATH),
                "/libs/" + XSSFilterImpl.DEFAULT_POLICY_PATH);
        context.registerInjectActivateService(new XSSFilterImpl());
        xssFilter = context.getService(XSSFilter.class);
        XSSFilterImpl xssFilterImpl = (XSSFilterImpl) xssFilter;
        XSSFilterImpl.AntiSamyPolicy antiSamyPolicy = xssFilterImpl.getActivePolicy();
        assertFalse("Expected a Resource based policy.", antiSamyPolicy.isEmbedded());
        assertEquals("This is not the policy we're looking for.", "/libs/" + XSSFilterImpl.DEFAULT_POLICY_PATH, antiSamyPolicy.getPath());
    }

    @Test
    public void testDefaultEmbeddedPolicy() {
        context.registerInjectActivateService(new XSSFilterImpl());
        xssFilter = context.getService(XSSFilter.class);
        XSSFilterImpl xssFilterImpl = (XSSFilterImpl) xssFilter;
        XSSFilterImpl.AntiSamyPolicy antiSamyPolicy = xssFilterImpl.getActivePolicy();
        assertTrue("Expected the default embedded policy.", antiSamyPolicy.isEmbedded());
        assertEquals("This is not the policy we're looking for.", XSSFilterImpl.EMBEDDED_POLICY_PATH, antiSamyPolicy.getPath());
    }

    @Test
    public void isValidHref() {
        context.registerInjectActivateService(new XSSFilterImpl());
        xssFilter = context.getService(XSSFilter.class);
        checkIsValid("javascript:alert(1)", false);
        checkIsValid("", true);
        checkIsValid("%26%23x6a%3b%26%23x61%3b%26%23x76%3b%26%23x61%3b%26%23x73%3b%26%23x63%3b%26%23x72%3b%26%23x69%3b%26%23x70%3b%26%23x74%3b%26%23x3a%3balert%281%29", false);
        checkIsValid("&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3a;alert(1)", false);
        checkIsValid("%-12", false);
        checkIsValid("/promotion/25%/", false);
        checkIsValid("#", true);
        checkIsValid("?foo=bar", true);
        checkIsValid("#javascript:alert(23)", true);
        checkIsValid("#\">", false);
    }

    private void checkIsValid(String input, boolean valid) {
        if (valid) {
            assertTrue("Expected valid href value for: " + input, xssFilter.isValidHref(input));
        } else {
            assertFalse("Expected invalid href value for: " + input, xssFilter.isValidHref(input));
        }
    }

}
