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
package org.apache.sling.xss.impl;

import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.adapter.AdapterFactory;
import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.xss.XSSAPI;
import org.jetbrains.annotations.NotNull;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferencePolicyOption;

@Component(
        service = AdapterFactory.class,
        property = {
                AdapterFactory.ADAPTER_CLASSES + "=org.apache.sling.xss.XSSAPI",
                AdapterFactory.ADAPTABLE_CLASSES + "=org.apache.sling.api.resource.ResourceResolver",
                AdapterFactory.ADAPTABLE_CLASSES + "=org.apache.sling.api.SlingHttpServletRequest"
        }
)
public class XSSAPIAdapterFactory implements AdapterFactory {

    @Reference(policyOption = ReferencePolicyOption.GREEDY)
    private XSSAPI xssapi;

    public XSSAPIAdapterFactory() {
        // default constructor for SCR
    }

    // constructor for testing, could use constructor injection with OSGi R7
    XSSAPIAdapterFactory(XSSAPI xssapi) {
        this.xssapi = xssapi;
    }

    @Override
    public <AdapterType> AdapterType getAdapter(@NotNull Object adaptable, @NotNull Class<AdapterType> type) {
        if (type == XSSAPI.class
                && (adaptable instanceof ResourceResolver || adaptable instanceof SlingHttpServletRequest)) {
            return type.cast(xssapi);
        }
        return null;
    }
}
