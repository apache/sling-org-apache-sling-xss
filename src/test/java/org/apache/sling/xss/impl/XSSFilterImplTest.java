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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;

import org.apache.sling.commons.metrics.Counter;
import org.apache.sling.commons.metrics.MetricsService;
import org.apache.sling.serviceusermapping.ServiceUserMapped;
import org.apache.sling.testing.mock.sling.junit5.SlingContext;
import org.apache.sling.testing.mock.sling.junit5.SlingContextExtension;
import org.apache.sling.xss.XSSFilter;
import org.apache.sling.xss.impl.status.XSSStatusService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

@ExtendWith(SlingContextExtension.class)
public class XSSFilterImplTest {

    static List<Object[]> dataForValidHref() {
        List<Object[]> testData = new ArrayList<>();
        testData.add(new Object[] {"javascript:alert(1)", false});
        testData.add(new Object[] {"", true});
        testData.add(new Object[] {"%26%23x6a%3b%26%23x61%3b%26%23x76%3b%26%23x61%3b%26%23x73%3b%26%23x63%3b%26%23x72%3b%26%23x69%3b%26%23x70%3b%26%23x74%3b%26%23x3a%3balert%281%29", false});
        testData.add(new Object[] {"&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3a;alert(1)", false});
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
        testData.add(new Object[] { "<link media=\"screen\">hello</link>", true });
        testData.add(new Object[] { "<link media=\"testingRege10\">hello</link>", true });
        testData.add(new Object[] { "<style media=\"screen\">h1 {color:red;}</style>", true });
        testData.add(new Object[] { "<link type=\"text/css\">valid Test</link>", true });
        testData.add(new Object[] { "<body bgcolor=\"black\">valid Test</body>", true });
        testData.add(new Object[] { "<div background=\"green\">invalid Test</div>", false });
        testData.add(new Object[] { "<table border=\"3\">valid Test</table>", true });
        testData.add(new Object[] { "<table border=\"green\">invalid Test</table>", false });
        testData.add(new Object[] { "<script>invalid Test</script>", false });
        testData.add(new Object[] { "", false });
        return testData;
    }

    public SlingContext context = new SlingContext();

    private XSSFilter xssFilter;

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
    }

    @Test
    public void testResourceBasedPolicy() {
        context.load().binaryFile(this.getClass().getClassLoader().getResourceAsStream(XSSFilterImpl.EMBEDDED_POLICY_PATH),
                "/libs/" + XSSFilterImpl.DEFAULT_POLICY_PATH);
        context.registerInjectActivateService(new XSSFilterImpl());
        xssFilter = context.getService(XSSFilter.class);
        XSSFilterImpl xssFilterImpl = (XSSFilterImpl) xssFilter;
        XSSFilterImpl.AntiSamyPolicy antiSamyPolicy = xssFilterImpl.getActivePolicy();
        assertFalse(antiSamyPolicy.isEmbedded(), "Expected a Resource based policy.");
        assertEquals("/libs/" + XSSFilterImpl.DEFAULT_POLICY_PATH, antiSamyPolicy.getPath(), "This is not the policy we're looking for.");
    }

    @Test
    public void testDefaultEmbeddedPolicy() {
        context.registerInjectActivateService(new XSSFilterImpl());
        xssFilter = context.getService(XSSFilter.class);
        XSSFilterImpl xssFilterImpl = (XSSFilterImpl) xssFilter;
        XSSFilterImpl.AntiSamyPolicy antiSamyPolicy = xssFilterImpl.getActivePolicy();
        assertTrue(antiSamyPolicy.isEmbedded(), "Expected the default embedded policy.");
        assertEquals(XSSFilterImpl.EMBEDDED_POLICY_PATH, antiSamyPolicy.getPath(), "This is not the policy we're looking for.");
    }

    @ParameterizedTest
    @MethodSource("dataForCheckMethod")
    public void testCheckMethod(String input, boolean isValid) {
        context.registerInjectActivateService(new XSSFilterImpl());
        xssFilter = context.getService(XSSFilter.class);
        System.out.println(input);
        if (isValid) {
            assertTrue(xssFilter.check(XSSFilter.DEFAULT_CONTEXT, input), "Expected valid input value for: " + input);
        } else {
            assertFalse(xssFilter.check(XSSFilter.DEFAULT_CONTEXT, input), "Expected invalid input value for: " + input);
        }
    }

    @ParameterizedTest
    @MethodSource("dataForValidHref")
    public void isValidHref(String input, boolean isValid) {
        context.registerInjectActivateService(new XSSFilterImpl());
        xssFilter = context.getService(XSSFilter.class);
        if (isValid) {
            assertTrue(xssFilter.isValidHref(input), "Expected valid href value for: " + input);
        } else {
            assertFalse(xssFilter.isValidHref(input), "Expected invalid href value for: " + input);
        }
    }

    @Test
    public void testFallbackFiltering() {
        final String longURLContext = "<a href=\"https://sling.apache.org" +
                "/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.\">Click</a>";
        context.registerInjectActivateService(new XSSFilterImpl());
        xssFilter = context.getService(XSSFilter.class);
        assertNotNull(xssFilter);
        assertEquals(longURLContext, xssFilter.filter(longURLContext));
    }
}
