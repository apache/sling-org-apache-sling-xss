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
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.apache.sling.xss.impl.xml.AntiSamyPolicy;
import org.owasp.html.DynamicAttributesSanitizerPolicy;
import org.owasp.html.Handler;
import org.owasp.html.HtmlStreamEventReceiver;
import org.owasp.html.HtmlStreamRenderer;
import org.owasp.html.PolicyFactory;

public class HtmlSanitizer {

    private AntiSamyPolicyAdapter customPolicy;
    private Map policies;
    private Set<String> textContainers;

    public HtmlSanitizer(AntiSamyPolicy policy) {
        this.customPolicy = new AntiSamyPolicyAdapter(policy);
        policies = reflectionGetPolicies(customPolicy.getHtmlCleanerPolicyFactory());
        textContainers = reflectionGetTextContainers(customPolicy.getHtmlCleanerPolicyFactory());
    }

    public SanitizedResult scan(String taintedHTML) {
        StringBuilder sb = new StringBuilder(taintedHTML.length());
        HtmlStreamEventReceiver out = HtmlStreamRenderer.create(sb, Handler.DO_NOTHING);
        DynamicAttributesSanitizerPolicy dynamicPolicy = new DynamicAttributesSanitizerPolicy(out, policies,
                textContainers, customPolicy.getDynamicAttributesPolicyMap(), customPolicy.getOnInvalidRemoveTagList());

        org.owasp.html.HtmlSanitizer.sanitize(taintedHTML, dynamicPolicy,
                customPolicy.getCssValidator().newStyleTagProcessor());
        return new SanitizedResult(sb.toString(), dynamicPolicy.getNumberOfErrors());
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