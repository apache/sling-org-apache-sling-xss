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
import org.apache.sling.xss.impl.xml.Policy;

/**
 * Class that provides the capability of securing input provided as plain text for HTML output.
 */
public class PolicyHandler {

    private final Policy policy;
    private Policy fallbackPolicy;
    private AntiSamyHtmlSanitizer antiSamy;
    private AntiSamyHtmlSanitizer fallbackAntiSamy;

    /**
     * Creates a {@code PolicyHandler} from an {@link InputStream}.
     *
     * @param policyStream the InputStream from which to read this handler's {@link Policy}
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
            this.policy = Policy.getInstance(bais);
            bais.reset();
            this.antiSamy = new AntiSamyHtmlSanitizer(this.policy);
            this.fallbackPolicy = new FallbackSlingPolicy(bais);
            this.fallbackAntiSamy = new AntiSamyHtmlSanitizer(this.fallbackPolicy);
        } finally {
            currentThread.setContextClassLoader(cl);
        }
    }

    public Policy getPolicy() {
        return this.policy;
    }

    public AntiSamyHtmlSanitizer getAntiSamy() {
        return this.antiSamy;
    }

    public AntiSamyHtmlSanitizer getFallbackAntiSamy() {
        return fallbackAntiSamy;
    }
}
