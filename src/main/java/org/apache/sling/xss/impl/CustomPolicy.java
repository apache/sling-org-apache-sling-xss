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

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import javax.annotation.Nullable;

import org.apache.sling.xss.impl.style.CssValidator;
import org.apache.sling.xss.impl.xml.Attribute;
import org.apache.sling.xss.impl.xml.Policy;
import org.apache.sling.xss.impl.xml.Tag;
import org.apache.sling.xss.impl.Constants;
import org.owasp.html.AttributePolicy;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;

import com.google.common.base.Predicate;

public class CustomPolicy {
    private PolicyFactory policyFactory;
    private List<String> onInvalidRemoveTagList = new ArrayList<>();
    private Map<String, AttributePolicy> dynamicAttributesPolicyMap = new HashMap<>();
    private CssValidator cssValidator;


    public CustomPolicy(Policy policy) {
        removeAttributeGuards();
        HtmlPolicyBuilder policyBuilder = new HtmlPolicyBuilder();

        cssValidator = new CssValidator(policy.getCssPolicy());

        // ------------ this is for the global attributes -------------
        Map<String, Attribute> globalAttributes = policy.getGlobalAttributes();
        for (Attribute attribute : globalAttributes.values()) {

            if (attribute.getOnInvalid().equals(Constants.REMOVE_TAG_STRING)) {
                onInvalidRemoveTagList.add(attribute.getName());
            }

            if (CssValidator.STYLE_ATTRIBUTE_NAME.equals(attribute.getName())) {
                // we match style tags separately
                policyBuilder.allowAttributes(attribute.getName()).matching(cssValidator.newCssAttributePolicy())
                        .globally();
            } else {
                List<String> allowedValuesFromAttribute = attribute.getLiterals();
                for (String allowedValue : allowedValuesFromAttribute) {
                    policyBuilder.allowAttributes(attribute.getName()).matching(true, allowedValue).globally();
                }

                List<Pattern> regexsFromAttribute = attribute.getPatternList();
                if (!regexsFromAttribute.isEmpty()) {
                    policyBuilder.allowAttributes(attribute.getName()).matching(matchesToPatterns(regexsFromAttribute))
                            .globally();
                } else {
                    policyBuilder.allowAttributes(attribute.getName()).globally();
                }

            }
        }

        // ------------ this is for the allowed emty tags -------------
        List<String> allowedEmptyTags = policy.getAllowedEmptyTags();
        for (String allowedEmptyTag : allowedEmptyTags) {
            policyBuilder.allowWithoutAttributes(allowedEmptyTag);
        }

        // ------------ this is for the tag rules -------------
        Map<String, Tag> tagMap = policy.getTagRules();
        for (Map.Entry<String, Tag> tag : tagMap.entrySet()) {

            String tagAction = tag.getValue().getAction();
            switch (tagAction) {
                // Tag.action
                case Constants.TRUNCATE:
                    policyBuilder.allowElements(tag.getValue().getName());

                    break;
                // filter: remove tags, but keep content,
                case Constants.FILTER:
                    break;
                // remove: remove tag and contents
                case Constants.REMOVE:
                    policyBuilder.disallowElements(tag.getValue().getName());
                    break;

                case Constants.VALIDATE:
                case "":
                    policyBuilder.allowElements(tag.getValue().getName());
                    boolean styleSeen = false;
                    // get the allowed Attributes for the tag
                    Map<String, Attribute> allowedAttributes = tag.getValue().getAttributeMap();
                    // if there are allowed Attributes, map over them
                    for (Attribute attribute : allowedAttributes.values()) {
                        if (attribute.getOnInvalid().equals(Constants.REMOVE_TAG_STRING)) {
                            onInvalidRemoveTagList.add(attribute.getName());
                        }
                        if (CssValidator.STYLE_ATTRIBUTE_NAME.equals(attribute.getName()))
                            styleSeen = true;
                        List<String> allowedValuesFromAttribute = attribute.getLiterals();
                        for (String allowedValue : allowedValuesFromAttribute) {
                            policyBuilder.allowAttributes(attribute.getName()).matching(true, allowedValue)
                                    .onElements(tag.getValue().getName());
                        }

                        List<Pattern> regexsFromAttribute = attribute.getPatternList();
                        if (!regexsFromAttribute.isEmpty()) {
                            policyBuilder.allowAttributes(attribute.getName())
                                    .matching(matchesToPatterns(regexsFromAttribute))
                                    .onElements(tag.getValue().getName());
                        } else {
                            policyBuilder.allowAttributes(attribute.getName()).onElements(tag.getValue().getName());
                        }
                    }

                    if (!styleSeen) {
                        policyBuilder.allowAttributes(CssValidator.STYLE_ATTRIBUTE_NAME)
                                .matching(cssValidator.newCssAttributePolicy()).onElements(tag.getValue().getName());
                    }
                    break;
                default:
                    throw new RuntimeException("No tag action found.");
            }
        }

        // disallow style tag on specific elements
        policyBuilder.disallowAttributes(CssValidator.STYLE_ATTRIBUTE_NAME)
                .onElements(cssValidator.getDisallowedTagNames().toArray(new String[0]));

        // ---------- dynamic attributes ------------
        Map<String, Attribute> dynamicAttributes = new HashMap<>();
        // checks if the dynamic attributes are allowed
        if (policy.getDirectives().get(Constants.ALLOW_DYNAMIC_ATTRIBUTES_STRING).equals("true")) {
            dynamicAttributes.putAll(policy.getDynamicAttributes());
            for (Attribute attribute : dynamicAttributes.values()) {
                if (attribute.getOnInvalid().equals(Constants.REMOVE_TAG_STRING)) {
                    onInvalidRemoveTagList.add(attribute.getName());
                }

                List<Pattern> regexsFromAttribute = attribute.getPatternList();
                for (Pattern regex : regexsFromAttribute) {
                    dynamicAttributesPolicyMap.put(attribute.getName(), newDynamicAttributePolicy(regex));
                }
                List<String> allowedValuesFromAttribute = attribute.getLiterals();

                if (!allowedValuesFromAttribute.isEmpty()) {
                    dynamicAttributesPolicyMap.put(attribute.getName(),
                            newDynamicAttributePolicy(true, allowedValuesFromAttribute.toArray(new String[0])));
                }

            }
        }

        policyFactory = policyBuilder.allowTextIn(CssValidator.STYLE_TAG_NAME).toFactory();

    }

    public PolicyFactory getCustomPolicyFactory() {
        return policyFactory;
    }

    public Map<String, AttributePolicy> getDynamicAttributesPolicyMap() {
        return dynamicAttributesPolicyMap;
    }

    public List<String> getOnInvalidRemoveTagList() {
        return onInvalidRemoveTagList;
    }

    public CssValidator getCssValidator() {
        return cssValidator;
    }

    private static Predicate<String> matchesToPatterns(List<Pattern> patternList) {
        return new Predicate<String>() {
            @Override
            public boolean apply(String s) {
                for (Pattern pattern : patternList) {
                    if (pattern.matcher(s).matches()) {
                        return true;
                    }
                }
                return false;
            }
        };
    }

    public AttributePolicy newDynamicAttributePolicy(final Pattern pattern) {
        return new AttributePolicy() {
            @Override
            public @Nullable String apply(String elementName, String attributeName, String value) {
                return pattern.matcher(value).matches() ? value : null;
            }
        };
    }

    public AttributePolicy newDynamicAttributePolicy(boolean ignoreCase, String... allowedValues) {
        final List<String> allowed = Arrays.asList(allowedValues);
        return new AttributePolicy() {
            @Override
            public @Nullable String apply(String elementName, String attributeName, String uncanonValue) {
                String value = ignoreCase ? uncanonValue.toLowerCase() : uncanonValue;
                return allowed.contains(value) ? value : null;
            }
        };
    }

    // java html sanitizer has some default Attribute Guards, which we don't want. So we are removing them here
    private void removeAttributeGuards() {
        try {
            Field guards = HtmlPolicyBuilder.class.getDeclaredField("ATTRIBUTE_GUARDS");
            letMeIn(guards);
            Map value = (Map) guards.get(null);
            Map newValue = new HashMap();
            guards.set(null, newValue);
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException(e);
        }
    }

    private void letMeIn(Field field) throws ReflectiveOperationException {
        if (!field.isAccessible())
            field.setAccessible(true);
        if ((field.getModifiers() & Modifier.FINAL) != 0) {
            Field modifiersField = Field.class.getDeclaredField("modifiers");
            modifiersField.setAccessible(true);
            modifiersField.setInt(field, field.getModifiers() & ~Modifier.FINAL);
        }
    }

}
