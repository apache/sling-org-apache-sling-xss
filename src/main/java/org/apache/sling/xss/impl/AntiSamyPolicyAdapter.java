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

import org.apache.sling.xss.impl.style.CssValidator;
import org.apache.sling.xss.impl.xml.Attribute;
import org.apache.sling.xss.impl.xml.AntiSamyPolicy;
import org.apache.sling.xss.impl.xml.Tag;
import org.jetbrains.annotations.Nullable;
import org.owasp.html.AttributePolicy;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;

import com.google.common.base.Predicate;

public class AntiSamyPolicyAdapter {
    private static final String ALLOW_DYNAMIC_ATTRIBUTES = "allowDynamicAttributes";
    private static final String REMOVE_TAG_ON_INVALID_ACTION = "removeTag";

    private final List<String> onInvalidRemoveTagList = new ArrayList<>();
    private final Map<String, AttributePolicy> dynamicAttributesPolicyMap = new HashMap<>();

    private PolicyFactory policyFactory;
    private CssValidator cssValidator;

    public AntiSamyPolicyAdapter(AntiSamyPolicy policy) {
        removeAttributeGuards();
        HtmlPolicyBuilder policyBuilder = new HtmlPolicyBuilder();

        cssValidator = new CssValidator(policy.getCssPolicy());

        // ------------ this is for the global attributes -------------
        Map<String, Attribute> globalAttributes = policy.getGlobalAttributes();

        for (Attribute attribute : globalAttributes.values()) {
            if (attribute.getOnInvalid().equals(REMOVE_TAG_ON_INVALID_ACTION)) {
                onInvalidRemoveTagList.add(attribute.getName());
            }

            if (CssValidator.STYLE_ATTRIBUTE_NAME.equals(attribute.getName())) {
                // we match style tags separately
                policyBuilder.allowAttributes(attribute.getName()).matching(cssValidator.newCssAttributePolicy())
                        .globally();
            } else {
                List<String> literalList = attribute.getLiterals();
                List<Pattern> patternList = attribute.getPatternList();

                if (!literalList.isEmpty() && !patternList.isEmpty()) {
                    // if both, the patterns and the literals are not empty, the value should be checked with them with an OR and not with an AND.
                    policyBuilder.allowAttributes(attribute.getName())
                        .matching(matchesPatternsOrLiterals(patternList, true, literalList))
                        .globally();
                }
                else if (!literalList.isEmpty()) {
                    policyBuilder.allowAttributes(attribute.getName())
                        .matching(true, literalList.toArray(new String[0]))
                        .globally();
                }
                else if (!patternList.isEmpty()) {
                    policyBuilder.allowAttributes(attribute.getName())
                            .matching(matchesToPatterns(patternList))
                            .globally();
                } else {
                    policyBuilder.allowAttributes(attribute.getName()).globally();
                }
            }
        }

        // ------------ this is for the allowed empty tags -------------
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
                case AntiSamyActions.TRUNCATE:
                    policyBuilder.allowElements(tag.getValue().getName());
                    break;

                // filter: remove tags, but keep content,
                case AntiSamyActions.FILTER:
                    break;

                // remove: remove tag and contents
                case AntiSamyActions.REMOVE:
                    policyBuilder.disallowElements(tag.getValue().getName());
                    break;

                case AntiSamyActions.VALIDATE:
                case "":
                    policyBuilder.allowElements(tag.getValue().getName());
                    boolean styleSeen = false;
                    // get the allowed Attributes for the tag
                    Map<String, Attribute> allowedAttributes = tag.getValue().getAttributeMap();
                    // if there are allowed Attributes, map over them
                    for (Attribute attribute : allowedAttributes.values()) {

                        if (attribute.getOnInvalid().equals(REMOVE_TAG_ON_INVALID_ACTION)) {
                            onInvalidRemoveTagList.add(attribute.getName());
                        }

                        styleSeen = CssValidator.STYLE_ATTRIBUTE_NAME.equals(attribute.getName());

                        List<String> literalList = attribute.getLiterals();
                        List<Pattern> patternList = attribute.getPatternList();

                        if (!literalList.isEmpty() && !patternList.isEmpty()) {
                            // if both, the patterns and the literals are not empty, the value should be checked with them with an OR and not with an AND.
                            policyBuilder.allowAttributes(attribute.getName())
                                .matching(matchesPatternsOrLiterals(patternList, true, literalList))
                                .onElements(tag.getValue().getName());
                        }
                        else if (!literalList.isEmpty()) {
                            policyBuilder.allowAttributes(attribute.getName())
                                .matching(true, literalList.toArray(new String[0]))
                                .onElements(tag.getValue().getName());
                            policyBuilder.allowAttributes(attribute.getName()).onElements(tag.getValue().getName());
                        }
                        else if (!patternList.isEmpty()) {
                            policyBuilder.allowAttributes(attribute.getName())
                                    .matching(matchesToPatterns(patternList))
                                    .onElements(tag.getValue().getName());
                        }
                    }

                    if (!styleSeen) {
                        policyBuilder.allowAttributes(CssValidator.STYLE_ATTRIBUTE_NAME)
                                .matching(cssValidator.newCssAttributePolicy()).onElements(tag.getValue().getName());
                    }
                    break;

                default:
                    throw new IllegalArgumentException("No tag action found.");
            }
        }

        // disallow style tag on specific elements
        policyBuilder.disallowAttributes(CssValidator.STYLE_ATTRIBUTE_NAME)
                .onElements(cssValidator.getDisallowedTagNames().toArray(new String[0]));

        // ---------- dynamic attributes ------------
        Map<String, Attribute> dynamicAttributes = new HashMap<>();

        // checks if the dynamic attributes are allowed
        if (policy.getDirectives().get(ALLOW_DYNAMIC_ATTRIBUTES).equals("true")) {
            dynamicAttributes.putAll(policy.getDynamicAttributes());
            for (Attribute attribute : dynamicAttributes.values()) {
                if (attribute.getOnInvalid().equals(REMOVE_TAG_ON_INVALID_ACTION)) {
                    onInvalidRemoveTagList.add(attribute.getName());
                }

                List<Pattern> regexsFromAttribute = attribute.getPatternList();
                List<String> allowedValuesFromAttribute = attribute.getLiterals();

                dynamicAttributesPolicyMap.put(attribute.getName(), newDynamicAttributePolicy(regexsFromAttribute, true, allowedValuesFromAttribute));
            }
        }

        policyFactory = policyBuilder.allowTextIn(CssValidator.STYLE_TAG_NAME).toFactory();

    }

    public PolicyFactory getHtmlCleanerPolicyFactory() {
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

    private static Predicate<String> matchesPatternsOrLiterals(List<Pattern> patternList, boolean ignoreCase, List<String> literalList) {
        return new Predicate<String>() {
            public boolean apply(String s) {
                // check if the string matches to the pattern or one of the literal
                s = ignoreCase ? s.toLowerCase() : s;
                return matchesToPatterns(patternList).apply(s) || literalList.contains(s);
            }
        };
    }

    public AttributePolicy newDynamicAttributePolicy(final List<Pattern> patternList, final boolean ignoreCase, final List<String> literalList) {
        return new AttributePolicy() {
            @Override
            public @Nullable String apply(String elementName, String attributeName, String value) {
                if (!literalList.isEmpty() && !patternList.isEmpty()) {
                    return matchesPatternsOrLiterals(patternList, ignoreCase, literalList).apply(value) ? value : null;

                } else if (!literalList.isEmpty()) {
                    value = ignoreCase ? value.toLowerCase() : value;
                    return literalList.contains(value) ? value : null;

                } else if (!patternList.isEmpty()) {
                    return matchesToPatterns(patternList).apply(value) ? value : null;
                }
                return null;
            }
        };
    }

    // java html sanitizer has some default Attribute Guards, which we don't want.
    // So we are removing them here
    private void removeAttributeGuards() {
        try {
            Field guards = HtmlPolicyBuilder.class.getDeclaredField("ATTRIBUTE_GUARDS");
            letMeIn(guards);
            guards.set(null, new HashMap<>());
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException(e);
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