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

/**
 * The result of cleaning untrusted CSS: the cleaned text, plus whether any disallowed content was
 * dropped while producing it. The drop indicator allows callers to count policy violations that would
 * otherwise be invisible, since cleaning always returns a (possibly empty) string.
 */
public class CleanedCss {

    private final String css;
    private final boolean droppedContent;

    CleanedCss(String css, boolean droppedContent) {
        this.css = css;
        this.droppedContent = droppedContent;
    }

    /**
     * Returns the cleaned CSS text.
     *
     * @return the cleaned CSS text, never {@code null}
     */
    public String getCss() {
        return css;
    }

    /**
     * Returns {@code true} when disallowed content (selectors, property values, {@code @import} or other
     * at-rules) was dropped while cleaning, i.e. the input was not violation-free.
     *
     * @return {@code true} if content was dropped, {@code false} otherwise
     */
    public boolean hasDroppedContent() {
        return droppedContent;
    }
}
