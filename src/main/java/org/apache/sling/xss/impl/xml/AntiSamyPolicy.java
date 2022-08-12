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
package org.apache.sling.xss.impl.xml;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import javax.xml.stream.XMLStreamException;

import org.apache.sling.xss.impl.PolicyException;

public class AntiSamyPolicy {

    protected final Map<String, Pattern> commonRegularExpressions = new HashMap<>();
    protected final Map<String, Attribute> commonAttributes = new HashMap<>();
    protected final Map<String, Tag> tagRules = new HashMap<>();
    protected final Map<String, Property> cssRules = new HashMap<>();
    protected final Map<String, String> directives = new HashMap<>();
    protected final Map<String, Attribute> globalAttributes = new HashMap<>();
    protected final Map<String, Attribute> dynamicAttributes = new HashMap<>();
    protected final List<String> requireClosingTags = new ArrayList<>();
    protected List<String> allowedEmptyTags = new ArrayList<>();

    public AntiSamyPolicy(InputStream input) throws PolicyException, XMLStreamException, IOException {
        AntiSamyXmlParser xmlParser = new AntiSamyXmlParser();
        MapBuilder mapBuilder = new MapBuilder();
        AntiSamyRules root = xmlParser.createRules(input);
        mapBuilder.createRulesMap(this, root);
    }

    public Map<String, String> getDirectives() {
        return directives;
    }

    public List<String> getRequireClosingTags() {
        return requireClosingTags;
    }

    public Map<String, Pattern> getCommonRegularExpressions() {
        return commonRegularExpressions;
    }

    public Map<String, Attribute> getGlobalAttributes() {
        return globalAttributes;
    }

    public Map<String, Attribute> getCommonAttributes() {
        return commonAttributes;
    }

    public Map<String, Property> getCssRules() {
        return cssRules;
    }

    public List<String> getAllowedEmptyTags() {
        return allowedEmptyTags;
    }

    public Map<String, Tag> getTagRules() {
        return tagRules;
    }

    public Map<String, Attribute> getDynamicAttributes() {
        return dynamicAttributes;
    }

    public CssPolicy getCssPolicy() {
        return new CssPolicy(cssRules,
                commonRegularExpressions);
    }

    public static class CssPolicy {

        private final Map<String, Property> cssRules;
        private final IncludeExcludeMatcher elementMatcher;
        private final IncludeExcludeMatcher classMatcher;
        private final IncludeExcludeMatcher idMatcher;
        private final IncludeExcludeMatcher pseudoElementMatcher;
        private final IncludeExcludeMatcher attributeMatcher;

        public CssPolicy(Map<String, Property> cssrules, Map<String, Pattern> commonRegExps) {
            this.cssRules = Collections.unmodifiableMap(cssrules);
            this.elementMatcher = new IncludeExcludeMatcher(commonRegExps.get("cssElementSelector"),
                    commonRegExps.get("cssElementExclusion"));
            this.classMatcher = new IncludeExcludeMatcher(commonRegExps.get("cssClassSelector"),
                    commonRegExps.get("cssClassExclusion"));
            this.idMatcher = new IncludeExcludeMatcher(commonRegExps.get("cssIDSelector"),
                    commonRegExps.get("cssIDExclusion"));
            this.pseudoElementMatcher = new IncludeExcludeMatcher(commonRegExps.get("cssPseudoElementSelector"),
                    commonRegExps.get("cssPseudoElementExclusion"));
            this.attributeMatcher = new IncludeExcludeMatcher(commonRegExps.get("cssAttributeSelector"),
                    commonRegExps.get("cssAttributeExclusion"));
        }

        public Map<String, Property> getCssRules() {
            return cssRules;
        }

        public boolean isValidElementName(String name) {
            return elementMatcher.matches(name);
        }

        public boolean isValidClassName(String name) {
            return classMatcher.matches(name);
        }

        public boolean isValidId(String name) {
            return idMatcher.matches(name);
        }

        public boolean isValidPseudoElementName(String name) {
            return pseudoElementMatcher.matches(name);
        }

        public boolean isValidAttributeSelector(String name) {
            return attributeMatcher.matches(name);
        }
    }
}