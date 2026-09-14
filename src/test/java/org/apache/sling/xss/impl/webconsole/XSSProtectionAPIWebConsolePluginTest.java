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
package org.apache.sling.xss.impl.webconsole;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.PrintWriter;
import java.io.StringWriter;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class XSSProtectionAPIWebConsolePluginTest {

    @Test
    public void testConsoleRootIsNotDerivedFromTheRawRequestUri() throws Exception {
        XSSProtectionAPIWebConsolePlugin plugin = new XSSProtectionAPIWebConsolePlugin();
        HttpServletRequest request = mock(HttpServletRequest.class);
        // servlet containers strip path parameters (;name=value) before servlet mapping, so a request with
        // this URI still routes to the plugin; the raw URI must never be reflected into the response, since
        // escapeHtml4 does not encode single quotes
        when(request.getRequestURI()).thenReturn("/system/console;v='onerror='alert(document.cookie)/xssprotection");
        when(request.getPathInfo()).thenReturn("/xssprotection");
        when(request.getContextPath()).thenReturn("");
        when(request.getServletPath()).thenReturn("/system/console");

        HttpServletResponse response = mock(HttpServletResponse.class);
        StringWriter output = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(output));

        plugin.doGet(request, response);

        String markup = output.toString();
        assertFalse(markup.contains("onerror"), "Expected the raw request URI to not be reflected into markup.");
        assertTrue(
                markup.contains("<script src=\"/system/console/xssprotection/webconsole/xss.js\"></script>"),
                "Expected the script tag to use the container-provided console root in a double-quoted attribute.");
    }

    @Test
    public void testConsoleRootPrefersTheFelixAppRootAttribute() throws Exception {
        XSSProtectionAPIWebConsolePlugin plugin = new XSSProtectionAPIWebConsolePlugin();
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getAttribute("felix.webconsole.appRoot")).thenReturn("/ctx/system/console");
        when(request.getPathInfo()).thenReturn("/xssprotection");

        HttpServletResponse response = mock(HttpServletResponse.class);
        StringWriter output = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(output));

        plugin.doGet(request, response);

        assertTrue(
                output.toString()
                        .contains("<script src=\"/ctx/system/console/xssprotection/webconsole/xss.js\"></script>"),
                "Expected the script tag to use the Felix Web Console appRoot request attribute.");
    }
}
