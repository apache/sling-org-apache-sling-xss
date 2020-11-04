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

import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.resource.Resource;
import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.xss.XSSAPI;
import org.junit.Before;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.isA;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;

public class XSSAPIAdapterFactoryTest {

    private XSSAPIAdapterFactory factory;

    @Before
    public void setup() {
        final XSSAPI xssapi = mock(XSSAPI.class);
        factory = new XSSAPIAdapterFactory(xssapi);
    }

    @Test
    public void testAdaptFromResourceResolver() {
        final ResourceResolver resolver = mock(ResourceResolver.class);

        assertThat("should adapt ResourceResolver to XSSAPI",
                factory.getAdapter(resolver, XSSAPI.class), isA(XSSAPI.class));
    }

    @Test
    public void testAdaptFromRequest() {
        final SlingHttpServletRequest request = mock(SlingHttpServletRequest.class);

        assertThat("should adapt SlingHttpServletRequest to XSSAPI",
                factory.getAdapter(request, XSSAPI.class), isA(XSSAPI.class));
    }

    @Test
    public void testNoAdaptionFromArbitraryObject() {
        assertThat("should not adapt Object to XSSAPI",
                factory.getAdapter(new Object(), XSSAPI.class), nullValue());
    }

    @Test
    public void testNoAdaptionFromRequestToResource() {
        final SlingHttpServletRequest request = mock(SlingHttpServletRequest.class);

        assertThat("should not adapt SlingHttpServletRequest to Resource",
                factory.getAdapter(request, Resource.class), nullValue());
    }
}