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
import org.apache.sling.xss.impl.xml.PolicyProvider;

/**
 * Class that provides the capability of securing input provided as plain text for HTML output.
 */
public class PolicyHandler {

    private final PolicyProvider policy;
    private PolicyProvider fallbackPolicy;
    private HtmlSanitizer htmlSanitizer;
    private HtmlSanitizer fallbackHtmlSanitizer;

    /**
     * Creates a {@code PolicyHandler} from an {@link InputStream}.
     *
     * @param policyStream the InputStream from which to read this handler's {@link PolicyProvider}
     */
    public PolicyHandler(InputStream policyStream) throws Exception {
        // fix for classloader issue with IBM JVM: see bug #31946
        // (currently: http://bugs.day.com/bugzilla/show_bug.cgi?id=31946)
        Thread currentThread = Thread.currentThread();
        ClassLoader cl = currentThread.getContextClassLoader();
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            currentThread.setContextClassLoader(this.getClass().getClassLoader());
            IOUtils.copy(policyStream, baos);
            ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
            currentThread.setContextClassLoader(this.getClass().getClassLoader());
            this.policy = new PolicyProvider(bais);
            bais.reset();
            this.htmlSanitizer = new HtmlSanitizer(this.policy);
            this.fallbackPolicy = new FallbackSlingPolicy(bais);
            this.fallbackHtmlSanitizer = new HtmlSanitizer(this.fallbackPolicy);
        } finally {
            currentThread.setContextClassLoader(cl);
        }
    }

    public PolicyProvider getPolicy() {
        return this.policy;
    }

    public HtmlSanitizer getHtmlSanitizer() {
        return this.htmlSanitizer;
    }

    public HtmlSanitizer getFallbackHtmlSanitizer() {
        return fallbackHtmlSanitizer;
    }
}
