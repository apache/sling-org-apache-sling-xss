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
package org.apache.sling.xss.impl.style;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sling.xss.impl.xml.AntiSamyPolicy.CssPolicy;
import org.owasp.html.AttributePolicy;
import org.owasp.html.HtmlStreamEventProcessor;

public class CssValidator {

    public static final String STYLE_TAG_NAME = "style";
    public static final String STYLE_ATTRIBUTE_NAME = STYLE_TAG_NAME;

    private final BatikCssCleaner cssParser;
    private final List<String> disallowedTagNames = new ArrayList<>();

    /*
     The attribute policies and style tag processors created below are baked into a shared, reusable
     PolicyFactory, so they cannot carry per-scan state themselves. Scans are synchronous on the calling
     thread, so a thread-local counter gives each scan its own CSS violation count (see
     org.apache.sling.xss.impl.HtmlSanitizer#scan).
    */
    private final ThreadLocal<AtomicInteger> cssViolations = ThreadLocal.withInitial(AtomicInteger::new);

    public CssValidator(CssPolicy cssPolicy) {
        cssParser = new BatikCssCleaner(cssPolicy);
    }

    public HtmlStreamEventProcessor newStyleTagProcessor() {
        return new StyleTagProcessor(cssParser, this::reportDroppedContent);
    }

    public AttributePolicy newCssAttributePolicy() {
        return (String elementName, String attributeName, String value) -> {
            CleanedCss cleaned = cssParser.cleanStyleDeclaration(value);
            if (cleaned.hasDroppedContent()) {
                // count the violation so that XSSFilter#check does not report input as clean
                // when filtering would strip parts of it
                reportDroppedContent();
            }
            return cleaned.getCss();
        };
    }

    public List<String> getDisallowedTagNames() {
        return Collections.unmodifiableList(disallowedTagNames);
    }

    /**
     * Resets the CSS violation count recorded for the current thread. Must be called before a scan starts.
     */
    public void resetCssViolationCount() {
        cssViolations.get().set(0);
    }

    /**
     * Returns the number of CSS violations (dropped selectors, property values, {@code @import} or other
     * at-rules) recorded on the current thread since the last call to {@link #resetCssViolationCount()}.
     *
     * @return the number of CSS violations recorded for the current thread
     */
    public int getCssViolationCount() {
        return cssViolations.get().get();
    }

    private void reportDroppedContent() {
        cssViolations.get().incrementAndGet();
    }
}
