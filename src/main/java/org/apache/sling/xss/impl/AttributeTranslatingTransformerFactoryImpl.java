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

import static javax.xml.XMLConstants.ACCESS_EXTERNAL_DTD;
import static javax.xml.XMLConstants.ACCESS_EXTERNAL_STYLESHEET;
import static javax.xml.XMLConstants.FEATURE_SECURE_PROCESSING;

import javax.xml.XMLConstants;
import javax.xml.transform.TransformerConfigurationException;

import org.apache.xalan.processor.TransformerFactoryImpl;

/**
 * Translates configuration calls to specific unsupported attributes to the {@link XMLConstants#FEATURE_SECURE_PROCESSING} feature
 *
 * <p>This is done in order to support AntiSamy 1.6.4 which requires the usage of a JAXP 1.5 compliant
 * transformer factory, which is Xalan is not. This implementation is minimal and not expected to be used
 * outside of this bundle.</p>
 *
 * @see <a href="https://github.com/nahsra/antisamy/issues/103">AntiSamy issue 103</a>
 */
public class AttributeTranslatingTransformerFactoryImpl extends TransformerFactoryImpl {

    @Override
    public void setAttribute(String name, Object value) throws IllegalArgumentException {
        if ( "".equals(value) &&  (
                ACCESS_EXTERNAL_DTD.equals(name) ||
                ACCESS_EXTERNAL_STYLESHEET.equals(name) ) ) {
            try {
                setFeature(FEATURE_SECURE_PROCESSING, true);
                return;
            } catch (TransformerConfigurationException e) {
                throw new IllegalArgumentException("Failed translating attribute " + name + " to feature " + FEATURE_SECURE_PROCESSING ,e);
            }
        }
        super.setAttribute(name, value);
    }
}
