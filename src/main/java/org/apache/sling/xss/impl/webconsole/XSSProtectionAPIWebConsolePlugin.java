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
package org.apache.sling.xss.impl.webconsole;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import javax.servlet.Servlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.sling.xss.XSSFilter;
import org.apache.sling.xss.impl.XSSFilterImpl;
import org.apache.sling.xss.impl.status.XSSStatusService;
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

    private static final Logger LOGGER = LoggerFactory.getLogger(XSSProtectionAPIWebConsolePlugin.class);
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

    private static final String URI_ROOT = "/system/console/" + LABEL;
    private static final String URI_CONFIG_XHR = URI_ROOT + "/config.xhr";
    private static final String URI_BLOCKED_XHR = URI_ROOT + "/blocked.xhr";
    private static final String URI_CONFIG_XML = URI_ROOT + "/config.xml";
    private static final String INTERNAL_RESOURCES_FOLDER = "/webconsole";
    private static final String RES_ROOT = URI_ROOT + INTERNAL_RESOURCES_FOLDER;
    private static final String RES_URI_PRETTIFY_CSS = RES_ROOT + "/prettify.css";
    private static final String RES_URI_PRETTIFY_JS = RES_ROOT + "/prettify.js";
    private static final String RES_URI_XSS_CSS = RES_ROOT + "/xss.css";
    private static final String RES_URI_XSS_JS = RES_ROOT + "/xss.js";
    private static final String RES_URI_BLOCKED_JS = RES_ROOT + "/blocked.js";
    private static final String RES_URI_CONFIG_JS = RES_ROOT + "/config.js";

    @Reference(target = "(component.name=org.apache.sling.xss.impl.XSSFilterImpl)")
    private XSSFilter xssFilter;

    @Reference
    private XSSStatusService statusService;

    private static final Set<String> CSS_RESOURCES = new HashSet<>(Arrays.asList(RES_URI_PRETTIFY_CSS, RES_URI_XSS_CSS));
    private static final Set<String> JS_RESOURCES = new HashSet<>(Arrays.asList(RES_URI_PRETTIFY_JS, RES_URI_XSS_JS, RES_URI_BLOCKED_JS,
            RES_URI_CONFIG_JS));

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String file = FilenameUtils.getName(request.getRequestURI());
        if (file != null && CSS_RESOURCES.contains(request.getRequestURI())) {
            try(InputStream cssStream =
                        getClass().getClassLoader().getResourceAsStream(INTERNAL_RESOURCES_FOLDER + "/" + file)) {
                if (cssStream != null) {
                    response.setContentType("text/css");
                    IOUtils.copy(cssStream, response.getOutputStream());
                }
            }
        } else if (file != null && JS_RESOURCES.contains(request.getRequestURI())) {
            try (InputStream jsStream =
                         getClass().getClassLoader().getResourceAsStream(INTERNAL_RESOURCES_FOLDER + "/" + file)) {
                if (jsStream != null) {
                    response.setContentType("application/javascript");
                    IOUtils.copy(jsStream, response.getOutputStream());
                }
            }
        } else if (URI_CONFIG_XHR.equalsIgnoreCase(request.getRequestURI()) && xssFilter != null) {
            response.setContentType("text/html");
            XSSFilterImpl xssFilterImpl = (XSSFilterImpl) xssFilter;
            XSSFilterImpl.AntiSamyPolicy antiSamyPolicy = xssFilterImpl.getActivePolicy();
            if (antiSamyPolicy != null) {
                PrintWriter printWriter = response.getWriter();
                printWriter.printf("<script type='text/javascript' src='%s'></script>\n", RES_URI_CONFIG_JS);
                printWriter.write("<div id='config'>");
                printWriter.printf("<link rel='stylesheet' type='text/css' href='%s'></link>\n", RES_URI_PRETTIFY_CSS);
                printWriter.printf("<script type='text/javascript' src='%s'></script>\n", RES_URI_PRETTIFY_JS);
                printWriter.write("<p class='statline ui-state-highlight'>The current AntiSamy configuration ");
                if (antiSamyPolicy.isEmbedded()) {
                    printWriter.write("is the default one embedded in the org.apache.sling.xss bundle.");
                } else {
                    printWriter.printf("is loaded from %s.", antiSamyPolicy.getPath());
                }
                printWriter.write("<button style='float:right' type='button' id='download-config'>Download</button></p>");
                String contents = "";
                try (InputStream configurationStream = antiSamyPolicy.read()) {
                    contents = IOUtils.toString(configurationStream, StandardCharsets.UTF_8);
                } catch (Throwable t) {
                    LOGGER.error("Unable to read policy file.", t);
                }
                printWriter.write("<pre class='prettyprint linenums'>");
                printWriter.write(StringEscapeUtils.escapeHtml4(contents));
                printWriter.write("</pre>");
                printWriter.write("</div>");
            }
        } else if (URI_BLOCKED_XHR.equalsIgnoreCase(request.getRequestURI())) {
            response.setContentType("text/html");
            PrintWriter printWriter = response.getWriter();
            printWriter.printf("<script type='text/javascript' src='%s'></script>\n", RES_URI_BLOCKED_JS);
            printWriter.println("<div id='blocked'>");
            printWriter.println("<div class='table'>");
            printWriter.println("<div class='ui-widget-header ui-corner-top buttonGroup'>Blocked URLs</div>");
            printWriter.println("<table class='nicetable tablesorter' id='invalid-urls'>");
            printWriter.println("<thead>");
            printWriter.println("<tr>");
            printWriter.println("<th class='header'>URL</th>");
            printWriter.println("<th class='header'>Times Blocked</th>");
            printWriter.println("</tr>");
            printWriter.println("</thead>");
            printWriter.println("<tbody>");
            int i = 1;
            for (Map.Entry<String, AtomicInteger> entry : statusService.getInvalidUrls().entrySet()) {
                String cssClass = ((i++ %2) == 0 ? "even" : "odd");
                printWriter.printf("<tr class='%s ui-state-default'>%n<td>%s</td><td>%d</td></tr>", cssClass, entry.getKey(),
                        entry.getValue().intValue());
            }
            printWriter.println("</tbody>");
            printWriter.println("</table>");
            printWriter.println("</div>");
            printWriter.println("</div>");
            printWriter.println("</div>");
        } else if (URI_CONFIG_XML.equalsIgnoreCase(request.getRequestURI()) && xssFilter != null) {
            response.setContentType("application/xml");
            response.setHeader("Content-Disposition", "attachment; filename=config.xml");
            XSSFilterImpl xssFilterImpl = (XSSFilterImpl) xssFilter;
            IOUtils.copy(xssFilterImpl.getActivePolicy().read(), response.getOutputStream());
            response.setStatus(HttpServletResponse.SC_OK);
        } else {
            PrintWriter printWriter = response.getWriter();
            printWriter.printf("<link rel='stylesheet' type='text/css' href='%s'>\n", RES_URI_XSS_CSS);
            printWriter.printf("<script type='text/javascript' src='%s'></script>\n", RES_URI_XSS_JS);
            printWriter.println("<div id='xss-tabs'>");
            printWriter.println("<ul>");
            printWriter.printf("<li><a href='%s'><span>Blocked URLs</span></a></li>\n", URI_BLOCKED_XHR);
            if (xssFilter != null) {
                printWriter.printf("<li><a href='%s'><span>Active Configuration</span></a></li>\n", URI_CONFIG_XHR);
            }
            printWriter.println("</ul>");
            printWriter.println("</div>");
        }
    }
}
