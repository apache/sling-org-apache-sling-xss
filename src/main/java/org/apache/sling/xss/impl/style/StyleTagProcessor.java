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
package org.apache.sling.xss.impl.style;

import java.util.List;

import org.owasp.html.HtmlStreamEventProcessor;
import org.owasp.html.HtmlStreamEventReceiver;

class StyleTagProcessor implements HtmlStreamEventProcessor {

    private final BatikCssCleaner cssCleaner;

    StyleTagProcessor(BatikCssCleaner cssCleaner) {
        this.cssCleaner = cssCleaner;
    }

    @Override
    public HtmlStreamEventReceiver wrap(HtmlStreamEventReceiver sink) {
        return new StyleTagReceiver(sink);
    }

    class StyleTagReceiver implements HtmlStreamEventReceiver {

        private final HtmlStreamEventReceiver wrapped;
        private boolean inStyleTag;

        StyleTagReceiver(HtmlStreamEventReceiver wrapped) {
            this.wrapped = wrapped;
        }

        @Override
        public void openDocument() {
            wrapped.openDocument();
        }

        @Override
        public void closeDocument() {
            wrapped.closeDocument();
        }

        @Override
        public void openTag(String elementName, List<String> attrs) {
            wrapped.openTag(elementName, attrs);
            inStyleTag = CssValidator.STYLE_TAG_NAME.equals(elementName);
        }

        @Override
        public void closeTag(String elementName) {
            wrapped.closeTag(elementName);
            inStyleTag = false;
        }

        @Override
        public void text(String taintedCss) {
            if (inStyleTag ) {
                wrapped.text(cssCleaner.cleanStylesheet(taintedCss));
            } else {
                wrapped.text(taintedCss);
            }
        }
    }
}
