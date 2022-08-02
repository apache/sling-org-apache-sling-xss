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

import org.apache.sling.xss.impl.xml.Policy;
import org.owasp.html.DynamicAttributesSanitizerPolicy;
import org.owasp.html.Handler;
import org.owasp.html.HtmlSanitizer;
import org.owasp.html.HtmlStreamEventReceiver;
import org.owasp.html.HtmlStreamRenderer;
import org.owasp.html.PolicyFactory;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;

public class AntiSamyHtmlSanitizer {

    private CustomPolicy custumPolicy;
    private ImmutableMap policies;
    private ImmutableSet<String> textContainers;

    public AntiSamyHtmlSanitizer() {
    }

    public AntiSamyHtmlSanitizer(Policy policy) {
        this.custumPolicy = new CustomPolicy(policy);
        policies = reflectionGetPolicies(custumPolicy.getCustomPolicyFactory());
        textContainers = reflectionGetTextContainers(custumPolicy.getCustomPolicyFactory());
    }

    public String scan(String taintedHTML) {
        StringBuilder sb = new StringBuilder(taintedHTML.length());
        HtmlStreamEventReceiver out = HtmlStreamRenderer.create(sb, Handler.DO_NOTHING);
        DynamicAttributesSanitizerPolicy dynamicPolice = new DynamicAttributesSanitizerPolicy(out, policies,
                textContainers, custumPolicy.getDynamicAttributesPolicyMap(), custumPolicy.getOnInvalidRemoveTagList());

        HtmlSanitizer.sanitize(taintedHTML, dynamicPolice, custumPolicy.getCssValidator().newStyleTagProcessor());
        return sb.toString();
    }

    private ImmutableSet<String> reflectionGetTextContainers(PolicyFactory policyFactory) {
        Class<?> c = policyFactory.getClass();
        try {
            Field field = c.getDeclaredField("textContainers");
            field.setAccessible(true);
            return (ImmutableSet<String>) field.get(policyFactory);
        } catch (NoSuchFieldException | SecurityException | IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }

    private ImmutableMap reflectionGetPolicies(PolicyFactory policyFactory) {
        Class<?> c = policyFactory.getClass();
        try {
            Field field = c.getDeclaredField("policies");
            field.setAccessible(true);
            return (ImmutableMap) field.get(policyFactory);
        } catch (NoSuchFieldException | SecurityException | IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }

    public String scan(String taintedHTML, Policy policy) throws Exception {
        if (taintedHTML == null) {
            throw new Exception("Null html input");
        }

        if (policy == null) {
            throw new Exception("No policy loaded");
        }
        return "safeHTML";
    }

}