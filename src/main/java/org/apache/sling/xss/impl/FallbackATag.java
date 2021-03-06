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

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;

import org.owasp.validator.html.model.Attribute;
import org.owasp.validator.html.model.Tag;

public class FallbackATag extends Tag {

    static final Attribute FALLBACK_HREF_ATTRIBUTE = new Attribute(
            "href",
            Arrays.asList(
                    XSSFilterImpl.ON_SITE_SIMPLIFIED,
                    XSSFilterImpl.OFF_SITE_SIMPLIFIED
            ),
            Collections.emptyList(),
            "removeAttribute", ""
    );

    private final Tag wrapped;

    public FallbackATag(Tag wrapped) {
        super("a", new HashMap<>(), "validate");
        this.wrapped = wrapped;
    }

    @Override
    public String getAction() {
        return wrapped.getAction();
    }

    @Override
    public boolean isAction(String action) {
        return wrapped.isAction(action);
    }

    @Override
    public Tag mutateAction(String action) {
        return wrapped.mutateAction(action);
    }

    @Override
    public String getRegularExpression() {
        return wrapped.getRegularExpression();
    }

    @Override
    public String getName() {
        return wrapped.getName();
    }

    @Override
    public Attribute getAttributeByName(String name) {
        if ("href".equalsIgnoreCase(name)) {
            return FALLBACK_HREF_ATTRIBUTE;
        }
        return wrapped.getAttributeByName(name);
    }
}
