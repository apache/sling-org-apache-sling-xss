/*******************************************************************************
 * Licensed to the Apache Software Foundation (ASF) under one or
 * more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information regarding
 * copyright ownership. The ASF licenses this file to you under the
 * Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0 Unless required by
 * applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 ******************************************************************************/
package org.apache.sling.xss.impl.xml;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import org.apache.sling.xss.impl.PolicyException;
import org.apache.sling.xss.impl.xml.Policy.CssPolicy;
import org.junit.jupiter.api.Test;

public class PolicyTest {

    @Test
    public void loadDefaultPolicy() throws Exception, PolicyException {
        InputStream input = Policy.class.getClassLoader().getResourceAsStream("SLING-INF/content/config.xml");
        Policy policy = Policy.getInstance(input);
        Map<String, Pattern> regexp = policy.getCommonRegularExpressions();
        List<String> empty = policy.getAllowedEmptyTags();
        List<String> closingTag = policy.getRequireClosingTags();
        Map<String, Attribute> global = policy.getGlobalAttributes();
        Map<String, Attribute> dynamic = policy.getDynamicAttributes();
        Map<String, Attribute> commonAttr = policy.getCommonAttributes();
        Map<String, Tag> tagRules = policy.getTagRules();
        Map<String, Property> cssRules = policy.getCssRules();
        Map<String, String> directives = policy.getDirectives();

        assertNotNull(policy);
        Tag imgTag = policy.getTagRules().get("img");
        assertNotNull(imgTag, "img tag rules");
        assertEquals(9, imgTag.getAttributeList().size(), "number of known img tag attributes");
        assertEquals(41, regexp.size(), "number of known common regexs");
        assertEquals(19, empty.size(), "number of known allowed emty tags");
        assertEquals(5, global.size(), "number of known global attributes");
        assertEquals(1, dynamic.size(), "number of known dynamic attributes");
        assertEquals(0, closingTag.size(), "number of known closing Tags");
        assertEquals(46, commonAttr.size(), "number of known common attributes");
        assertEquals(73, tagRules.size(), "number of known tag rules");
        assertEquals(118, cssRules.size(), "number of known css rules");
        assertEquals(12, directives.size(), "number of known directives");

        CssPolicy cssPolicy = policy.getCssPolicy();

        assertEquals(118, cssPolicy.getCssRules().size(), "cssPolicy.cssRules.size");
        assertTrue(cssPolicy.isValidElementName("base-link"));
        assertFalse(cssPolicy.isValidElementName("base|link"));
    }
}
