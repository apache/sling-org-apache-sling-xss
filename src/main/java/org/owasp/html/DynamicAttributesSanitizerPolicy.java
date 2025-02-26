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
package org.owasp.html;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import org.jetbrains.annotations.Nullable;

/**
 * Extends the default policy to support dynamic attributes.
 *
 * Since we want to support the antisamy config file, we have to make dynamic
 * tag attributes possible.
 * It is placed in the 'org.owasp.html' package because there are package
 * private fields.
 */
public class DynamicAttributesSanitizerPolicy extends ElementAndAttributePolicyBasedSanitizerPolicy {

    private Map<String, ElementAndAttributePolicies> elementAndAttrPolicies;
    private Map<String, AttributePolicy> dynamicAttributesPolicyMap;
    private List<String> onInvalidRemoveTagList;
    private int numberOfErrors;

    public DynamicAttributesSanitizerPolicy(
            HtmlStreamEventReceiver out,
            Map<String, ElementAndAttributePolicies> elAndAttrPolicies,
            Set<String> allowedTextContainers,
            Map<String, AttributePolicy> dynamicAttributesPolicyMap,
            List<String> onInvalidRemoveTagList) {
        super(out, elAndAttrPolicies, allowedTextContainers);
        this.elementAndAttrPolicies = elAndAttrPolicies;
        this.dynamicAttributesPolicyMap = dynamicAttributesPolicyMap;
        this.onInvalidRemoveTagList = onInvalidRemoveTagList;
    }

    @Override
    public void openTag(String elementName, List<String> attrs) {
        // StylingPolicy repeats some of this code because it is more complicated
        // to refactor it into multiple method bodies, so if you change this,
        // check the override of it in that class.
        if (elementName != null && attrs != null && elementAndAttrPolicies != null) {
            ElementAndAttributePolicies policies = elementAndAttrPolicies.get(elementName);

            String adjustedElementName = applyPolicies2(elementName, attrs, policies);
            if (adjustedElementName != null && !(attrs.isEmpty() && policies.htmlTagSkipType.skipAvailability())) {
                writeOpenTag(policies, adjustedElementName, attrs);
                return;
            }
            deferOpenTag(elementName);
        }
    }

    final @Nullable String applyPolicies2(
            String elementName, List<String> attrs, ElementAndAttributePolicies policies) {
        String adjustedElementName;
        Boolean removeTag = false;
        if (policies != null) {
            for (ListIterator<String> attrsIt = attrs.listIterator(); attrsIt.hasNext(); ) {
                String name = attrsIt.next();

                AttributePolicy attrPolicy = null;
                // check if the attribute name starts with an dynamic tag, to handle it specially
                for (Entry<String, AttributePolicy> dynamicAttributeEntry : dynamicAttributesPolicyMap.entrySet()) {
                    if (name.startsWith(dynamicAttributeEntry.getKey())) {
                        attrPolicy = dynamicAttributeEntry.getValue();
                        break;
                    }
                }
                // if it is not an dynamic attr it gets it's normal policy
                if (attrPolicy == null) {
                    attrPolicy = policies.attrPolicies.get(name);
                }

                // if there is no policy for this attribute, it gets removed
                if (attrPolicy == null) {
                    numberOfErrors++;
                    attrsIt.remove();
                    attrsIt.next();
                    attrsIt.remove();
                } else {
                    String value = attrsIt.next();
                    String adjustedValue = attrPolicy.apply(elementName, name, value);
                    if (adjustedValue == null) {
                        numberOfErrors++;
                        if (onInvalidRemoveTagList.contains(name)) {
                            removeTag = true;
                        }
                        attrsIt.remove();
                        attrsIt.previous();
                        attrsIt.remove();
                    } else {
                        attrsIt.set(adjustedValue);
                    }
                }
            }

            try {
                Method removeDuplicateAttributesMethod =
                        ElementAndAttributePolicyBasedSanitizerPolicy.class.getDeclaredMethod(
                                "removeDuplicateAttributes", List.class);
                removeDuplicateAttributesMethod.setAccessible(true);
                try {
                    removeDuplicateAttributesMethod.invoke(null, attrs);
                } catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
                    throw new RuntimeException(e);
                }
            } catch (NoSuchMethodException e) {
                throw new RuntimeException(e);
            }

            // checks if the onInvalid action of the invalid Tag is remove, and then removes
            // it
            adjustedElementName = Boolean.TRUE.equals(removeTag) ? null : policies.elPolicy.apply(elementName, attrs);
            if (adjustedElementName != null) {
                adjustedElementName = HtmlLexer.canonicalElementName(adjustedElementName);
            }
        } else {
            numberOfErrors++;
            adjustedElementName = null;
        }
        return adjustedElementName;
    }

    public int getNumberOfErrors() {
        return numberOfErrors;
    }
}
