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

import org.apache.sling.commons.metrics.Counter;
import org.apache.sling.commons.metrics.MetricsService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;

@Component(service = XSSMetricsService.class)
public class XSSMetricsService {

    private static final String COUNTER_INVALID_HREFS = "xss.invalid_hrefs";

    private final Counter invalidHrefs;

    @Activate
    public XSSMetricsService(@Reference MetricsService metricsService) {
        invalidHrefs = metricsService.counter(COUNTER_INVALID_HREFS);
    }

    public void invalidHref() {
        invalidHrefs.increment();
    }
}
