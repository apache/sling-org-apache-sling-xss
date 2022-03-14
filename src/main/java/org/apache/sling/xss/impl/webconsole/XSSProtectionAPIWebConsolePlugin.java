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

import javax.json.Json;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.json.JsonWriter;
import javax.servlet.Servlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.text.StringEscapeUtils;
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

    private static final String PLUGIN_ROOT_PATH = "/" + LABEL;
    private static final String URI_CONFIG_XHR = PLUGIN_ROOT_PATH + "/config.xhr";
    private static final String URI_BLOCKED_XHR = PLUGIN_ROOT_PATH + "/blocked.json";
    private static final String URI_CONFIG_XML = PLUGIN_ROOT_PATH + "/config.xml";
    private static final String INTERNAL_RESOURCES_FOLDER = "/webconsole";
    private static final String RES_ROOT = PLUGIN_ROOT_PATH + INTERNAL_RESOURCES_FOLDER;
    private static final String RES_URI_PRETTIFY_CSS = RES_ROOT + "/prettify.css";
    private static final String RES_URI_PRETTIFY_JS = RES_ROOT + "/prettify.js";
    private static final String RES_URI_XSS_CSS = RES_ROOT + "/xss.css";
    private static final String RES_URI_XSS_JS = RES_ROOT + "/xss.js";
    private static final String RES_URI_BLOCKED_JS = RES_ROOT + "/blocked.js";
    private static final String RES_URI_CONFIG_JS = RES_ROOT + "/config.js";
    public static final String SCRIPT_TAG = "<script src='%s'></script>\n";
    public static final String LINK_TAG = "<link rel='stylesheet' type='text/css' href='%s'>";

    @Reference(target = "(component.name=org.apache.sling.xss.impl.XSSFilterImpl)")
    private XSSFilter xssFilter;

    @Reference
    private XSSStatusService statusService;

    private static final Set<String> CSS_RESOURCES = new HashSet<>(Arrays.asList(RES_URI_PRETTIFY_CSS, RES_URI_XSS_CSS));
    private static final Set<String> JS_RESOURCES = new HashSet<>(Arrays.asList(RES_URI_PRETTIFY_JS, RES_URI_XSS_JS, RES_URI_BLOCKED_JS,
            RES_URI_CONFIG_JS));

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        String pluginResource = request.getPathInfo();
        String consoleRoot = request.getRequestURI().substring(0, request.getRequestURI().indexOf(pluginResource));
        if (CSS_RESOURCES.contains(pluginResource)) {
            streamResource(response, FilenameUtils.getName(pluginResource), "text/css");
        } else if (JS_RESOURCES.contains(pluginResource)) {
            streamResource(response, FilenameUtils.getName(pluginResource), "application/javascript");
        } else if (URI_CONFIG_XHR.equalsIgnoreCase(pluginResource) && xssFilter != null) {
            writeAntiSamyConfiguration(consoleRoot, response);
        } else if (URI_CONFIG_XML.equalsIgnoreCase(pluginResource) && xssFilter != null) {
            streamAntiSamyConfiguration(response);
        } else if (URI_BLOCKED_XHR.equalsIgnoreCase(pluginResource)) {
            generateInvalidUrlsJSONReport(response);
        } else {
            try {
                PrintWriter printWriter = response.getWriter();
                printWriter.printf(LINK_TAG, consoleRoot + RES_URI_XSS_CSS);
                printWriter.printf(SCRIPT_TAG, consoleRoot + RES_URI_XSS_JS);
                printWriter.println("<div id='xss-tabs'>");
                printWriter.println("<ul>");
                printWriter.println("<li id='blocked-tab'><a href='#blocked'><span>Status</span></a></li>");
                if (xssFilter != null) {
                    printWriter.println(
                            String.format("<li id='config-tab'><a href='%s'><span>Active Configuration</span></a></li>",
                                    consoleRoot + URI_CONFIG_XHR));
                }
                printWriter.println("</ul>");
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
                printWriter.println("<tbody id='invalid-urls-rows'>");
                printWriter.println("</tbody>");
                printWriter.println("</table>");
                printWriter.println("</div></div></div>");
            } catch (IOException e) {
                LOGGER.error("Unable to generate scaffold for the webconsole plugin output.", e);
            }
        }
    }

    private void streamAntiSamyConfiguration(HttpServletResponse response) {
        try {
            response.setContentType("application/xml");
            response.setHeader("Content-Disposition", "attachment; filename=config.xml");
            XSSFilterImpl xssFilterImpl = (XSSFilterImpl) xssFilter;
            IOUtils.copy(xssFilterImpl.getActivePolicy().read(), response.getOutputStream());
        } catch (IOException e) {
            LOGGER.error("Unable to stream AntiSamy configuration.", e);
        }

    }

    private void generateInvalidUrlsJSONReport(HttpServletResponse response) {
        JsonArrayBuilder hrefs = Json.createArrayBuilder();
        for (Map.Entry<String, AtomicInteger> entry : statusService.getInvalidUrls().entrySet()) {
            JsonObject href =
                    Json.createObjectBuilder().add("href", entry.getKey()).add("times", entry.getValue().intValue()).build();
            hrefs.add(href);
        }
        try (JsonWriter writer = Json.createWriter(response.getWriter())) {
            response.setContentType("application/json");
            writer.writeObject(Json.createObjectBuilder().add("hrefs", hrefs.build()).build());
        } catch (IOException e) {
            LOGGER.error("Unable to write JSON report for invalid URLs.", e);
        }

    }

    private void writeAntiSamyConfiguration(String consoleRoot, HttpServletResponse response) {
        response.setContentType("text/html");
        XSSFilterImpl xssFilterImpl = (XSSFilterImpl) xssFilter;
        XSSFilterImpl.AntiSamyPolicy antiSamyPolicy = xssFilterImpl.getActivePolicy();
        if (antiSamyPolicy != null) {
            try {
                PrintWriter printWriter = response.getWriter();
                printWriter.printf(SCRIPT_TAG, consoleRoot + RES_URI_CONFIG_JS);
                printWriter.write("<div id='config'>");
                printWriter.printf(LINK_TAG, consoleRoot + RES_URI_PRETTIFY_CSS);
                printWriter.printf(SCRIPT_TAG, consoleRoot + RES_URI_PRETTIFY_JS);
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
                }
                printWriter.write("<pre class='prettyprint linenums'>");
                printWriter.write(StringEscapeUtils.escapeHtml4(contents));
                printWriter.write("</pre>");
                printWriter.write("</div>");
            } catch (IOException e) {
                LOGGER.error("Unable to write the AntiSamy configuration tab.", e);
            }
        }
    }

    /**
     * Streams a resource embedded in the bundle.
     * @param response the response
     * @param file the file name
     * @param contentType the content type of the resource
     */
    private void streamResource(HttpServletResponse response, String file, String contentType) {
        try (InputStream cssStream =
                     getClass().getClassLoader().getResourceAsStream(INTERNAL_RESOURCES_FOLDER + "/" + file)) {
            if (cssStream != null) {
                response.setContentType(contentType);
                IOUtils.copy(cssStream, response.getOutputStream());
            }
        } catch (IOException e) {
            LOGGER.error(String.format("Unable to stream bundled resource %s.", file), e);
        }
    }
}
