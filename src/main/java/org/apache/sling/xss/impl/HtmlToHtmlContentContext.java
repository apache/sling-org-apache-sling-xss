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


import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class implements an escaping rule to be used for cleaning up existing HTML
 * content. The output will still be HTML.
 * <p>
 * The cleanup is performed using the AntiSamy library found at
 * <a href="http://www.owasp.org/index.php/AntiSamy">http://www.owasp.org/index.php/AntiSamy</a>
 */
public class HtmlToHtmlContentContext implements XSSFilterRule {

    /**
     * Logger
     */
    private final Logger log = LoggerFactory.getLogger(this.getClass());

    /**
     * @see XSSFilterRule#check(PolicyHandler, String)
     */
    @Override
    public boolean check(final PolicyHandler policyHandler, final String str) {
        if (StringUtils.isNotEmpty(str)) {
            ClassLoader tccl = Thread.currentThread().getContextClassLoader();
            try {
                Thread.currentThread().setContextClassLoader(this.getClass().getClassLoader());
                return true;
            } catch (final Exception se) {
                logError(se, str);
            } finally {
                Thread.currentThread().setContextClassLoader(tccl);
            }
        }
        return false;
    }

    /**
     * @see XSSFilterRule#filter(PolicyHandler, java.lang.String)
     */
    @Override
    public String filter(final PolicyHandler policyHandler, final String unsafeString) {
        if (StringUtils.isNotEmpty(unsafeString)) {
            try {
                final String results = getCleanResults(policyHandler, unsafeString);
                if (results != null) {
                    log.debug("Protected (HTML -> HTML):\n{}", results);
                    return results;
                }
            } catch (Exception e) {
                logError(e, unsafeString);
            }
        }
        return StringUtils.EMPTY;
    }

    /**
     * @see XSSFilterRule#supportsPolicy()
     */
    @Override
    public boolean supportsPolicy() {
        return true;
    }

    private String getCleanResults(PolicyHandler handler, String input) {
        String results;
        ClassLoader tccl = Thread.currentThread().getContextClassLoader();
        try {
            Thread.currentThread().setContextClassLoader(this.getClass().getClassLoader());
            results = handler.getAntiSamy().scan(input);
        } catch (StackOverflowError e) {
            log.debug("Will perform a second attempt at filtering the following input due to a StackOverflowError:\n{}", input);
            results = handler.getFallbackAntiSamy().scan(input);
            log.debug("Second attempt was successful.");
        } finally {
            Thread.currentThread().setContextClassLoader(tccl);
        }
        return results;
    }

    private void logError(Exception e, String input) {
        log.warn("Unable to check input.", e);
        log.debug("Provided input: {}", input);
    }
}
