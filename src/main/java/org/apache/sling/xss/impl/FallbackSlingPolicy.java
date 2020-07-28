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

import java.io.InputStream;

import org.owasp.validator.html.InternalPolicy;
import org.owasp.validator.html.PolicyException;
import org.owasp.validator.html.model.Tag;
import org.xml.sax.InputSource;

public class FallbackSlingPolicy extends InternalPolicy {

    private FallbackATag fallbackATag;
    private final Object aTagLock = new Object();

    public FallbackSlingPolicy(InputStream inputStream) throws PolicyException {
       super(null, getSimpleParseContext(getTopLevelElement(new InputSource(inputStream))));

    }

    @Override
    public Tag getTagByLowercaseName(String tagName) {
        if ("a".equalsIgnoreCase(tagName)) {
            synchronized (aTagLock) {
                if (fallbackATag == null) {
                    Tag wrapped = super.getTagByLowercaseName(tagName);
                    if (wrapped != null) {
                        fallbackATag = new FallbackATag(wrapped);
                    }
                }
            }
            if (fallbackATag != null) {
                return fallbackATag;
            }
        }
        return super.getTagByLowercaseName(tagName);
    }
}
