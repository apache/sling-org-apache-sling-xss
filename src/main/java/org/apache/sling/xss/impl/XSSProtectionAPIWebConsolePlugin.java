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

import java.io.IOException;
import java.io.InputStream;
import java.io.Writer;
import java.nio.charset.StandardCharsets;

import javax.servlet.Servlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.sling.xss.XSSFilter;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component(
        service = Servlet.class,
        property = {
                XSSProtectionAPIWebConsolePlugin.REG_PROP_LABEL + "=" + XSSProtectionAPIWebConsolePlugin.LABEL,
                XSSProtectionAPIWebConsolePlugin.REG_PROP_TITLE + "=" + XSSProtectionAPIWebConsolePlugin.TITLE,
                XSSProtectionAPIWebConsolePlugin.REG_PROP_CATEGORY + "=Sling"
        }
)
public class XSSProtectionAPIWebConsolePlugin extends HttpServlet {

    /*
        do not replace the following constants with the ones from org.apache.felix, since you'll create a wiring to those APIs; the
        current way this plugin is written allows it to optionally be available, if the Felix Web Console is installed on the OSGi
        platform where this bundle will be deployed
     */
    static final String REG_PROP_LABEL = "felix.webconsole.label";
    static final String REG_PROP_TITLE = "felix.webconsole.title";
    static final String REG_PROP_CATEGORY = "felix.webconsole.category";
    static final String LABEL = "xssprotection";
    static final String TITLE= "XSS Protection";

    private static final String RES_LOC = LABEL + "/res/ui";
    private static final Logger LOGGER = LoggerFactory.getLogger(XSSProtectionAPIWebConsolePlugin.class);

    @Reference(target = "(component.name=org.apache.sling.xss.impl.XSSFilterImpl)")
    private XSSFilter xssFilter;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (request.getRequestURI().endsWith(RES_LOC + "/prettify.css")) {
            try(InputStream cssStream = getClass().getClassLoader().getResourceAsStream("/res/ui/prettify.css")) {
                if (cssStream != null) {
                    response.setContentType("text/css");
                    IOUtils.copy(cssStream, response.getOutputStream());
                }
            }
        } else if (request.getRequestURI().endsWith(RES_LOC + "/prettify.js")) {
            try(InputStream jsStream = getClass().getClassLoader().getResourceAsStream("/res/ui/prettify.js")) {
                if (jsStream != null) {
                    response.setContentType("application/javascript");
                    IOUtils.copy(jsStream, response.getOutputStream());
                }
            }
        } else {
            if (xssFilter != null) {
                XSSFilterImpl xssFilterImpl = (XSSFilterImpl) xssFilter;
                XSSFilterImpl.AntiSamyPolicy antiSamyPolicy = xssFilterImpl.getActivePolicy();
                if (antiSamyPolicy != null) {
                    Writer w = response.getWriter();
                    w.write("<link rel=\"stylesheet\" type=\"text/css\" href=\"" + RES_LOC + "/prettify.css\"></link>");
                    w.write("<script type=\"text/javascript\" src=\"" + RES_LOC + "/prettify.js\"></script>");
                    w.write("<script type=\"text/javascript\" src=\"" + RES_LOC + "/fsclassloader.js\"></script>");
                    w.write("<script>$(document).ready(prettyPrint);</script>");
                    w.write("<style>.prettyprint ol.linenums > li { list-style-type: decimal; } pre.prettyprint { white-space: pre-wrap; " +
                            "}</style>");
                    w.write("<p class=\"statline ui-state-highlight\">The current AntiSamy configuration ");
                    if (antiSamyPolicy.isEmbedded()) {
                        w.write("is the default one embedded in the org.apache.sling.xss bundle.");
                    } else {
                        w.write("is loaded from ");
                        w.write(antiSamyPolicy.getPath());
                        w.write(".");
                    }
                    w.write("</p>");
                    String contents = "";
                    try(InputStream configurationStream = antiSamyPolicy.read()) {
                        contents = IOUtils.toString(configurationStream, StandardCharsets.UTF_8);
                    } catch (Throwable t) {
                        LOGGER.error("Unable to read policy file.", t);
                    }
                    w.write("<pre class=\"prettyprint linenums\">");
                    w.write(StringEscapeUtils.escapeHtml4(contents));
                    w.write("</pre>");
                }
            }

        }
    }
}
