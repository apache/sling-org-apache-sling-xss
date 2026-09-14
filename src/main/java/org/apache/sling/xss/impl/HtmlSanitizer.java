/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sling.xss.impl;

import java.lang.reflect.Field;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.apache.commons.lang3.StringUtils;
import org.apache.sling.xss.impl.style.CssValidator;
import org.apache.sling.xss.impl.xml.AntiSamyPolicy;
import org.owasp.html.DynamicAttributesSanitizerPolicy;
import org.owasp.html.Handler;
import org.owasp.html.HtmlStreamEventReceiver;
import org.owasp.html.HtmlStreamRenderer;
import org.owasp.html.PolicyFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class HtmlSanitizer {

    static final String MAX_INPUT_SIZE_DIRECTIVE = "maxInputSize";

    private static final Logger LOG = LoggerFactory.getLogger(HtmlSanitizer.class);

    private AntiSamyPolicyAdapter customPolicy;
    private Map policies;
    private Set<String> textContainers;
    private final int maxInputSize;

    public HtmlSanitizer(AntiSamyPolicy policy) {
        this.customPolicy = new AntiSamyPolicyAdapter(policy);
        policies = reflectionGetPolicies(customPolicy.getHtmlCleanerPolicyFactory());
        textContainers = reflectionGetTextContainers(customPolicy.getHtmlCleanerPolicyFactory());
        maxInputSize = parseMaxInputSize(policy);
    }

    /**
     * Reads the {@code maxInputSize} directive from the policy, matching the AntiSamy contract that
     * inputs larger than this limit are rejected. When the directive is absent no limit is applied
     * (backwards-compatible behavior); an unparseable value is reported and ignored.
     */
    private static int parseMaxInputSize(AntiSamyPolicy policy) {
        String value = policy.getDirectives().get(MAX_INPUT_SIZE_DIRECTIVE);
        if (value != null) {
            try {
                return Integer.parseInt(value.trim());
            } catch (NumberFormatException e) {
                LOG.warn("Ignoring invalid value '{}' of the {} policy directive.", value, MAX_INPUT_SIZE_DIRECTIVE);
            }
        }
        return Integer.MAX_VALUE;
    }

    public SanitizedResult scan(String taintedHTML) {
        if (taintedHTML.length() > maxInputSize) {
            // fail closed, matching the AntiSamy semantics of the maxInputSize directive: an empty
            // result with an error makes filter() return an empty string and check() return false
            LOG.warn(
                    "Rejecting input of {} characters as it exceeds the {} policy directive value of {}.",
                    taintedHTML.length(),
                    MAX_INPUT_SIZE_DIRECTIVE,
                    maxInputSize);
            return new SanitizedResult(StringUtils.EMPTY, 1);
        }
        StringBuilder sb = new StringBuilder(taintedHTML.length());
        HtmlStreamEventReceiver out = HtmlStreamRenderer.create(sb, Handler.DO_NOTHING);
        DynamicAttributesSanitizerPolicy dynamicPolicy = new DynamicAttributesSanitizerPolicy(
                out,
                policies,
                textContainers,
                customPolicy.getDynamicAttributesPolicyMap(),
                customPolicy.getOnInvalidRemoveTagList());

        CssValidator cssValidator = customPolicy.getCssValidator();
        cssValidator.resetCssViolationCount();
        org.owasp.html.HtmlSanitizer.sanitize(taintedHTML, dynamicPolicy, cssValidator.newStyleTagProcessor());
        // CSS cleaning rewrites style attributes and style tag contents outside of the policy object;
        // include its violations in the error count so that XSSFilter#check cannot report input as
        // violation-free while XSSFilter#filter would strip parts of it
        int numberOfErrors = dynamicPolicy.getNumberOfErrors() + cssValidator.getCssViolationCount();
        return new SanitizedResult(sb.toString(), numberOfErrors);
    }

    private Set<String> reflectionGetTextContainers(PolicyFactory policyFactory) {
        Class<?> c = policyFactory.getClass();
        try {
            Field field = c.getDeclaredField("textContainers");
            field.setAccessible(true);
            return (Set<String>) field.get(policyFactory);
        } catch (NoSuchFieldException | SecurityException | IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }

    private Map reflectionGetPolicies(PolicyFactory policyFactory) {
        Class<?> c = policyFactory.getClass();
        try {
            Field field = c.getDeclaredField("policies");
            field.setAccessible(true);
            return (Map) field.get(policyFactory);
        } catch (NoSuchFieldException | SecurityException | IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }

    public SanitizedResult scan(String taintedHTML, AntiSamyPolicy policy) {
        Objects.requireNonNull(taintedHTML, "Null html input");
        Objects.requireNonNull(policy, "Null policy loaded");

        return new HtmlSanitizer(policy).scan(taintedHTML);
    }
}
