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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.apache.sling.xss.impl.xml.Policy.CssPolicy;
import org.owasp.html.AttributePolicy;
import org.owasp.html.HtmlStreamEventProcessor;

public class CssValidator {

    public static String STYLE_TAG_NAME = "style";
    public static String STYLE_ATTRIBUTE_NAME = STYLE_TAG_NAME;

    private final BatikCssCleaner cssParser;
    private final List<String> disallowedTagNames = new ArrayList<>();

    public CssValidator(CssPolicy cssPolicy) {
        cssParser = new BatikCssCleaner(cssPolicy);
    }

    public HtmlStreamEventProcessor newStyleTagProcessor() {
        return new StyleTagProcessor(cssParser);
    }

    public AttributePolicy newCssAttributePolicy() {
        return new AttributePolicy() {
            @Override
            public String apply(String elementName, String attributeName, String value) {
                return cssParser.cleanStyleDeclaration(value);
            }
        };
    }

    public List<String> getDisallowedTagNames() {
        return Collections.unmodifiableList(disallowedTagNames);
    }
}
