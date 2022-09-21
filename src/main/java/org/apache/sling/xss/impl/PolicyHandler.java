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
package org.apache.sling.xss.impl;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;

import org.apache.commons.io.IOUtils;
import org.apache.sling.xss.impl.xml.AntiSamyPolicy;

/**
 * Class that provides the capability of securing input provided as plain text for HTML output.
 */
public class PolicyHandler {

    private final AntiSamyPolicy policy;
    private AntiSamyPolicy fallbackPolicy;
    private HtmlSanitizer htmlSanitizer;
    private HtmlSanitizer fallbackHtmlSanitizer;

    /**
     * Creates a {@code PolicyHandler} from an {@link InputStream}.
     *
     * @param policyStream the InputStream from which to read this handler's {@link AntiSamyPolicy}
     */
    public PolicyHandler(InputStream policyStream) throws Exception {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            IOUtils.copy(policyStream, baos);
            ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
            this.policy = new AntiSamyPolicy(bais);
            bais.reset();
            this.htmlSanitizer = new HtmlSanitizer(this.policy);
            this.fallbackPolicy = new FallbackSlingPolicy(bais);
            this.fallbackHtmlSanitizer = new HtmlSanitizer(this.fallbackPolicy);
        }
    }

    public AntiSamyPolicy getPolicy() {
        return this.policy;
    }

    public HtmlSanitizer getHtmlSanitizer() {
        return this.htmlSanitizer;
    }

    public HtmlSanitizer getFallbackHtmlSanitizer() {
        return fallbackHtmlSanitizer;
    }
}
