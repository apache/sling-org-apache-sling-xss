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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

import org.apache.sling.xss.impl.InvalidConfigException;

class MapBuilder {

    AntiSamyPolicy policy;
    // Antisamy hardcodes the allowed-empty-tags default:
    // https://github.com/nahsra/antisamy/blob/main/src/main/java/org/owasp/validator/html/scan/Constants.java#L37
    private static final List<String> ALLOWED_EMPTY_TAGS = Arrays.asList(
            "br",
            "hr",
            "a",
            "img",
            "link",
            "iframe",
            "script",
            "object",
            "applet",
            "frame",
            "base",
            "param",
            "meta",
            "input",
            "textarea",
            "embed",
            "basefont",
            "col");

    public void createRulesMap(AntiSamyPolicy policy, AntiSamyRules topLevelElement) throws InvalidConfigException {
        this.policy = policy;

        parseCommonRegExps(topLevelElement.getRegexpList());
        parseDirectives(topLevelElement.getDirectiveList());
        parseAllowedEmptyTags(topLevelElement.getAllowedEmptyTags());
        parseCommonAttributes(topLevelElement.getCommonAttributeList());
        parseGlobalAttributes(topLevelElement.getGlobalTagAttributes().getGlobalTagAttributeList());
        parseDynamicAttributes(topLevelElement.getDynamicTagAttribute().getDynamicTagAttributeList());
        parseTagRules(topLevelElement.getTagRulesList());

        parseCSSRules(topLevelElement.getPropertyList());
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
            policy.commonRegularExpressions.put(name, regexp);
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
            policy.directives.put(name, value);
        }
    }

    private void parseCommonAttributes(List<Attribute> root) {
        for (Attribute attribute : root) {
            List<Regexp> allowedRegexps = getAllowedRegexps(attribute.getRegexpList());
            Attribute newAttribute = new Attribute(attribute.getName(), allowedRegexps, attribute.getLiteralList(),
                    attribute.getOnInvalid(), attribute.getDescription());
            policy.commonAttributes.put(attribute.getName(), newAttribute);
        }
    }

    /**
    * Go through <allowed-empty-tags> section of the policy file.
    *
    * @param allowedEmptyTagsListNode Top level of <allowed-empty-tags>
    * @param allowedEmptyTags The tags that can be empty
    */
    private void parseAllowedEmptyTags(AllowedEmptyTags allowedEmptyTagsList) {
        if (allowedEmptyTagsList != null) {
            policy.allowedEmptyTags = allowedEmptyTagsList.getLiterals();
        } else
            policy.allowedEmptyTags.addAll(ALLOWED_EMPTY_TAGS);
    }

    /**
    * Go through <global-tag-attributes> section of the policy file.
    *
    * @param root Top level of <global-tag-attributes>
    * @param globalAttributes1 A HashMap of global Attributes that need
    validation
    * for every tag.
    * @param commonAttributes The common attributes
    * @throws InvalidConfigException
    */
    private void parseGlobalAttributes(List<Attribute> root) throws InvalidConfigException {
        for (Attribute ele : root) {
            String name = ele.getName();
            Attribute toAdd = policy.commonAttributes.get(name);

            if (toAdd != null)
                policy.globalAttributes.put(name, toAdd);
            else
                throw new InvalidConfigException("Global attribute '" + name
                        + "' was not defined in <common-attributes>");
        }
    }

    /**
    * Go through <dynamic-tag-attributes> section of the policy file.
    *
    * @param root Top level of <dynamic-tag-attributes>
    * @param dynamicAttributes A HashMap of dynamic Attributes that need
    validation
    * for every tag.
    * @param commonAttributes The common attributes
    * @throws InvalidConfigException
    */

    private void parseDynamicAttributes(List<Attribute> root) throws InvalidConfigException {
        for (Attribute ele : root) {
            String name = ele.getName();
            Attribute toAdd = policy.getCommonAttributes().get(name);

            if (toAdd != null) {
                String attrName = name.substring(0, name.length() - 1);
                policy.getDynamicAttributes().put(attrName, toAdd);
            } else
                throw new InvalidConfigException("Dynamic attribute '" + name
                        + "' was not defined in <common-attributes>");
        }
    }

    private void parseTagRules(List<Tag> root) throws InvalidConfigException {
        if (root == null)
            return;

        for (Tag tagNode : root) {
            String name = tagNode.getName();
            String action = tagNode.getAction();

            List<Attribute> attributeList = tagNode.getAttributeList();
            List<Attribute> tagAttributes = getTagAttributes(attributeList, name);
            Tag tag = new Tag(name, action, tagAttributes);

            policy.tagRules.put(name, tag);
        }
    }

    private List<Attribute> getTagAttributes(List<Attribute> attributeList, String tagName)
            throws InvalidConfigException {
        List<Attribute> tagAttributes = new ArrayList<>();

        for (Attribute attribute : attributeList) {
            Attribute newAttribute;
            String attributeName = attribute.getName();
            List<Regexp> regexps = attribute.getRegexpList();
            List<Literal> literals = attribute.getLiteralList();
            String onInvalid = attribute.getOnInvalid();
            String description = attribute.getDescription();

            // attribute has no children
            if (regexps.isEmpty() && literals.isEmpty()) {
                Attribute commonAttribute = policy.commonAttributes.get(attributeName);
                if (commonAttribute != null) {
                    // creates a new Attribute with the fetched Attribute's information if not
                    // available
                    newAttribute = new Attribute(attributeName,
                            !regexps.isEmpty() ? regexps : commonAttribute.getRegexpList(),
                            !literals.isEmpty() ? literals : commonAttribute.getLiteralList(),
                            !onInvalid.isEmpty() ? onInvalid : commonAttribute.getOnInvalid(),
                            !description.isEmpty() ? description : commonAttribute.getDescription());
                } else {
                    throw new InvalidConfigException("Attribute '" + attributeName +
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

    private void parseCSSRules(List<Property> root) {

        for (Property property : root) {
            List<Regexp> allowedRegexp3 = getAllowedRegexps(property.getRegexpList());
            Property propertyWithPatterns = new Property(property.getName(), allowedRegexp3, property.getLiteralList(),
                    property.getShorthandList(), property.getDescription(), property.getOnInvalid(),
                    property.getDefaultValue());
            policy.getCssRules().put(property.getName(), propertyWithPatterns);
        }
    }

    private List<Regexp> getAllowedRegexps(List<Regexp> nameAndRegexpsList) {
        List<Regexp> allowedRegExp = new ArrayList<>();
        for (Regexp regExpNode : nameAndRegexpsList) {
            String regExpName = regExpNode.getName();
            String value = regExpNode.getValue();

            if (regExpName != null && regExpName.length() > 0) {
                allowedRegExp
                        .add(new Regexp(regExpName, policy.getCommonRegularExpressions().get(regExpName).toString()));
            } else if (value != null) {
                allowedRegExp.add(new Regexp(regExpName, value));
            }
        }
        return allowedRegExp;
    }
}