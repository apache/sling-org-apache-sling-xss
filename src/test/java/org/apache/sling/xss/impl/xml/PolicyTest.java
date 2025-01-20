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
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import org.apache.sling.xss.impl.HtmlSanitizer;
import org.apache.sling.xss.impl.xml.AntiSamyPolicy.CssPolicy;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.converter.ArgumentConversionException;
import org.junit.jupiter.params.converter.ConvertWith;
import org.junit.jupiter.params.converter.TypedArgumentConverter;
import org.junit.jupiter.params.provider.ValueSource;

class PolicyTest {

    @Test
    void loadDefaultPolicy() throws Exception {
        try (InputStream input = AntiSamyPolicy.class.getClassLoader().getResourceAsStream("SLING-INF/content/config.xml")) {
            AntiSamyPolicy policy = new AntiSamyPolicy(input);
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

            // SLING-12622 -- getPattern() must not return null even if no regexp is specified
            Attribute hrefAttr = commonAttr.get("href");
            Regexp onsiteUrl = hrefAttr.getRegexpList().get(0);
            assertEquals("onsiteURL",onsiteUrl.getName());
            assertNotNull(onsiteUrl.getPattern());

            assertEquals(73, tagRules.size(), "number of known tag rules");
            assertEquals(118, cssRules.size(), "number of known css rules");
            assertEquals(12, directives.size(), "number of known directives");

            CssPolicy cssPolicy = policy.getCssPolicy();
            assertEquals(118, cssPolicy.getCssRules().size(), "cssPolicy.cssRules.size");
            assertTrue(cssPolicy.isValidElementName("base-link"));
            assertFalse(cssPolicy.isValidElementName("base|link"));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "configWithoutDifferentCaseDuplicateLiterals.xml",
            "configWithoutHref.xml",
            "configWithAdditionalGlobalAndDynamicConditions.xml"
    })
    void loadPolicyFile(@Resource Path configFile) throws Exception {
        try (InputStream input = Files.newInputStream(configFile)) {
            AntiSamyPolicy policy = new AntiSamyPolicy(input);
            assertNotNull(policy);
            HtmlSanitizer htmlSanitizer = new HtmlSanitizer(policy);
            assertNotNull(htmlSanitizer);
        }
    }

    @Target({ElementType.PARAMETER})
    @Retention(RetentionPolicy.RUNTIME)
    @ConvertWith(LoadResource.class)
    @interface Resource {}

    private static class LoadResource extends TypedArgumentConverter<String, Path> {

        LoadResource() {
            super(String.class, Path.class);
        }

        @Override
        protected Path convert(String relPath) throws ArgumentConversionException {
            URL url = LoadResource.class.getClassLoader().getResource(relPath);
            assertNotNull(url, "resource not found: " + relPath);
            try {
                return Paths.get(url.toURI());
            } catch (URISyntaxException e) {
                throw new RuntimeException(e);
            }
        }
    }
}
