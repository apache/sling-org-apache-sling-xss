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
package org.apache.sling.xss.impl.style;

import java.io.IOException;
import java.io.StringReader;

import org.apache.batik.css.parser.Parser;
import org.apache.sling.xss.impl.xml.Policy.CssPolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.css.sac.CSSException;
import org.w3c.css.sac.InputSource;

public class BatikCssCleaner {

    private final Logger logger = LoggerFactory.getLogger(getClass());
    private final CssPolicy cssPolicy;

    private static final String CDATA_PRE = "<![CDATA[";
    private static final String CDATA_POST = "]]>";

    public BatikCssCleaner(CssPolicy cssPolicy) {
        this.cssPolicy = cssPolicy;
    }

    /**
     * Parses a CSS stylesheet and returns it in a safe form
     *
     * @param untrustedCss a complete CSS stylesheet
     * @return the cleaned CSS stylesheet text
     */
    public String cleanStylesheet(String untrustedCss) {
        try {
            if ( untrustedCss.startsWith(CDATA_PRE) && untrustedCss.endsWith(CDATA_POST) )
                untrustedCss = untrustedCss.substring(CDATA_PRE.length(), untrustedCss.length() - CDATA_POST.length());
            Parser parser = new Parser();
            ValidatingDocumentHandler handler = new ValidatingDocumentHandler(cssPolicy, false);
            parser.setDocumentHandler(handler);
            parser.parseStyleSheet(new InputSource(new StringReader(untrustedCss)));
            return handler.getValidCss();
        } catch (CSSException | IOException e) {
            logger.debug("Unexpected error while cleaning stylesheet", e);
            return "";
        }
    }

    /**
     * Parses a CSS style declaration (i.e. the text of a <tt>style</tt> attribute) and returns it in a safe form
     *
     * @param untrustedCss a css style declaration
     * @return the cleaned CSS style declaration
     */
    public String cleanStyleDeclaration(String untrustedCss) {
        try {
            Parser parser = new Parser();
            ValidatingDocumentHandler handler = new ValidatingDocumentHandler(cssPolicy, true);
            parser.setDocumentHandler(handler);
            parser.parseStyleDeclaration(new InputSource(new StringReader(untrustedCss)));
            return handler.getValidCss();
        } catch (CSSException | IOException e) {
            logger.debug("Unexpected error while cleaning style declaration", e);
            return "";
        }
    }
}
