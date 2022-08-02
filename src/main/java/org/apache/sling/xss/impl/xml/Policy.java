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

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

import org.apache.sling.xss.impl.Constants;
import org.apache.sling.xss.impl.PolicyException;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ctc.wstx.stax.WstxInputFactory;
import com.ctc.wstx.stax.WstxOutputFactory;
import com.fasterxml.jackson.dataformat.xml.XmlMapper;

public class Policy {

    private static final String DIRECTIVE_EMBED_STYLE_SHEETS = "embedStyleSheets";

    public static class CssPolicy {

        private final Map<String, Property> cssRules;
        private final IncludeExcludeMatcher elementMatcher;
        private final IncludeExcludeMatcher classMatcher;
        private final IncludeExcludeMatcher idMatcher;
        private final IncludeExcludeMatcher pseudoElementMatcher;
        private final IncludeExcludeMatcher attributeMatcher;

        public CssPolicy(Map<String, Property> cssrules, Map<String, Pattern> commonRegExps, Map<String, String> directives) {
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

    protected final Map<String, Pattern> commonRegularExpressions = new HashMap<>();
    protected final Map<String, Attribute> commonAttributes = new HashMap<>();
    protected final Map<String, Tag> tagRules = new HashMap<>();
    protected final Map<String, Property> cssRules = new HashMap<>();
    protected final Map<String, String> directives = new HashMap<>();
    protected final Map<String, Attribute> globalAttributes = new HashMap<>();
    protected final Map<String, Attribute> dynamicAttributes = new HashMap<>();
    protected List<String> allowedEmptyTags = new ArrayList<>();
    protected final List<String> requireClosingTags = new ArrayList<>();

    private final Logger logger = LoggerFactory.getLogger(getClass());

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
                commonRegularExpressions, directives);
    }

    protected Policy(InputStream input) throws PolicyException, XMLStreamException, IOException {
        AntiSamyRules root = null;
        root = getTopLevelElement(input);
        init(root);
    }

    public static Policy getInstance(InputStream bais) throws PolicyException, XMLStreamException, IOException {
        return new Policy(bais);
    }

    public Tag getTagByLowercaseName(String a) {
        return tagRules.get(a);
    }

    public AntiSamyRules getTopLevelElement(InputStream input)
            throws IOException, XMLStreamException {
        XMLInputFactory xmlInputFactory = new WstxInputFactory();
        XMLStreamReader xmlStreamReader;
        AntiSamyRules antiSamyRules = null;
        xmlStreamReader = xmlInputFactory.createXMLStreamReader(input);
        XmlMapper mapper = new XmlMapper(xmlInputFactory, new WstxOutputFactory());
        antiSamyRules = mapper.readValue(xmlStreamReader, AntiSamyRules.class);
        if ( "true".equals(antiSamyRules.getDirectivesByName().get(DIRECTIVE_EMBED_STYLE_SHEETS)) ) {
            logger.warn("Unsupported configuration directive {} is set to true and will be ignored", DIRECTIVE_EMBED_STYLE_SHEETS);
        }
        return antiSamyRules;
    }

    private void init(AntiSamyRules topLevelElement) throws PolicyException {
        parseCommonRegExps(topLevelElement.getRegexpList());
        parseDirectives(topLevelElement.getDirectiveList());
        parseCommonAttributes(topLevelElement.getCommonAttributeList());
        parseGlobalAttributes(topLevelElement.getGlobalTagAttributes().getGlobalTagAttributeList());
        parseDynamicAttributes(topLevelElement.getDynamicTagAttribute().getDynamicTagAttributeList());
        parseTagRules(topLevelElement.getTagRulesList());
        parseCSSRules(topLevelElement.getPropertyList());

        parseAllowedEmptyTags(topLevelElement.getAllowedEmptyTags());
    }

    /**
     * Go through the <common-regexps> section of the policy file.
     *
     * @param root                      Top level of <common-regexps>
     */
    private void parseCommonRegExps(List<Regexp> root) {
        for (Regexp regex : root) {
            String name = regex.getName();
            Pattern regexp = Pattern.compile(regex.getValue(),
                    Pattern.DOTALL);
            commonRegularExpressions.put(name, regexp);
        }
    }

    /**
     * Go through <directives> section of the policy file.
     *
     * @param root       Top level of <directives>
     */
    private void parseDirectives(List<Directive> root) {
        for (Directive directive : root) {
            String name = directive.getName();
            String value = directive.getValue();
            directives.put(name, value);
        }
    }

    private void parseCommonAttributes(List<Attribute> root) {

        for (Attribute attribute : root) {

            List<Regexp> allowedRegexps = getAllowedRegexps(attribute.getRegexpList());
            Attribute newAttribute = new Attribute(attribute.getName(), allowedRegexps, attribute.getLiteralList(),
                    attribute.getOnInvalid(), attribute.getDescription());
            commonAttributes.put(attribute.getName().toLowerCase(), newAttribute);
        }

    }

    // /**
    // * Go through <allowed-empty-tags> section of the policy file.
    // *
    // * @param allowedEmptyTagsListNode Top level of <allowed-empty-tags>
    // * @param allowedEmptyTags The tags that can be empty
    // */
    private void parseAllowedEmptyTags(AllowedEmptyTags allowedEmptyTagsList) throws PolicyException {
        if (allowedEmptyTagsList != null) {
            allowedEmptyTags = allowedEmptyTagsList.getLiterals();
        } else
            allowedEmptyTags.addAll(Constants.ALLOWED_EMPTY_TAGS);
    }

    // /**
    // * Go through <global-tag-attributes> section of the policy file.
    // *
    // * @param root Top level of <global-tag-attributes>
    // * @param globalAttributes1 A HashMap of global Attributes that need
    // validation
    // * for every tag.
    // * @param commonAttributes The common attributes
    // * @throws PolicyException
    // */
    private void parseGlobalAttributes(List<Attribute> root) throws PolicyException {
        for (Attribute ele : root) {

            String name = ele.getName();
            Attribute toAdd = commonAttributes.get(name.toLowerCase());

            if (toAdd != null)
                globalAttributes.put(name.toLowerCase(), toAdd);
            else
                throw new PolicyException("Global attribute '" + name
                        + "' was not defined in <common-attributes>");
        }
    }

    // /**
    // * Go through <dynamic-tag-attributes> section of the policy file.
    // *
    // * @param root Top level of <dynamic-tag-attributes>
    // * @param dynamicAttributes A HashMap of dynamic Attributes that need
    // validation
    // * for every tag.
    // * @param commonAttributes The common attributes
    // * @throws PolicyException
    // */

    private void parseDynamicAttributes(List<Attribute> root) throws PolicyException {
        for (Attribute ele : root) {

            String name = ele.getName();
            Attribute toAdd = commonAttributes.get(name.toLowerCase());

            if (toAdd != null) {
                String attrName = name.toLowerCase().substring(0, name.length() - 1);
                dynamicAttributes.put(attrName, toAdd);
            } else
                throw new PolicyException("Dynamic attribute '" + name
                        + "' was not defined in <common-attributes>");
        }
    }

    private List<Regexp> getAllowedRegexps(List<Regexp> nameAndRegexpsList) {
        List<Regexp> allowedRegExp = new ArrayList<>();
        for (Regexp regExpNode : nameAndRegexpsList) {
            String regExpName = regExpNode.getName();
            String value = regExpNode.getValue();

            if (regExpName != null && regExpName.length() > 0) {
                allowedRegExp
                        .add(new Regexp(regExpName, commonRegularExpressions.get(regExpName).toString()));
            } else if (value != null) {
                allowedRegExp.add(new Regexp(regExpName, value));
            }
        }
        return allowedRegExp;
    }

    private void parseTagRules(List<Tag> root) throws PolicyException {
        if (root == null)
            return;

        for (Tag tagNode : root) {
            String name = tagNode.getName();
            String action = tagNode.getAction();

            List<Attribute> attributeList = tagNode.getAttributeList();
            List<Attribute> tagAttributes = getTagAttributes(attributeList, name);
            Tag tag = new Tag(name, action, tagAttributes);

            tagRules.put(name.toLowerCase(), tag);
        }
    }

    private List<Attribute> getTagAttributes(List<Attribute> attributeList, String tagName)
            throws PolicyException {

        List<Attribute> tagAttributes = new ArrayList<>();
        for (Attribute attribute : attributeList) {
            Attribute newAttribute;
            String attributeName = attribute.getName().toLowerCase();
            List<Regexp> regexps = attribute.getRegexpList();
            List<Literal> literals = attribute.getLiteralList();
            String onInvalid = attribute.getOnInvalid();
            String description = attribute.getDescription();

            // attribute has no children
            if (regexps.isEmpty() && literals.isEmpty()) {
                Attribute commonAttribute = commonAttributes.get(attributeName);
                if (commonAttribute != null) {
                    // creates a new Attribute with the fetched Attribute's information if not
                    // available
                    newAttribute = new Attribute(attributeName,
                            !regexps.isEmpty() ? regexps : commonAttribute.getRegexpList(),
                            !literals.isEmpty() ? literals : commonAttribute.getLiteralList(),
                            !onInvalid.isEmpty() ? onInvalid : commonAttribute.getOnInvalid(),
                            !description.isEmpty() ? description : commonAttribute.getDescription());
                } else {
                    throw new PolicyException("Attribute '" + attributeName +
                            "' was referenced as a common attribute in definition of '" + tagName +
                            "', but does not exist in <common-attributes>");
                }

            } else {
                List<Regexp> commonAllowedRegexps = getAllowedRegexps(regexps);
                List<Literal> allowedValues = attribute.getLiteralList();
                newAttribute = new Attribute(attributeName, commonAllowedRegexps, allowedValues, onInvalid,
                        description);

            }
            // Add fully built attribute.
            tagAttributes.add(newAttribute);
        }
        return tagAttributes;

    }

    private void parseCSSRules(
            List<Property> root) throws PolicyException {

        for (Property property : root) {
            List<Regexp> allowedRegexp3 = getAllowedRegexps(property.getRegexpList());
            Property propertyWithPatterns = new Property(property.getName(), allowedRegexp3, property.getLiteralList(),
                    property.getShorthandList(), property.getDescription(), property.getOnInvalid(),
                    property.getDefaultValue());
            cssRules.put(property.getName().toLowerCase(), propertyWithPatterns);
        }
    }

}
