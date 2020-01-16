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
package org.apache.sling.xss.impl.status;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.jetbrains.annotations.NotNull;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;

/**
 * The {@code XSSLibraryStatusService} collects information about the way the XSS Protection API library is used.
 */
@Component(service = XSSStatusService.class)
@Designate(ocd = XSSStatusService.Configuration.class)
public class XSSStatusService {

    @ObjectClassDefinition(
            name = "Apache Sling XSS Status Service",
            description = "The XSS Protection API Status Service provides various statistics about how the library was used."
    )
    @interface Configuration {
        @AttributeDefinition(
                name = "Maximum number of recorded invalid URLs",
                description = "Once this number is reached, previously recorded invalid URLs will be discarded."
        )
        int maxNumberOfInvalidUrlsRecorded() default MAX_INVALID_URLS_RECORDED;
    }

    public static final int MAX_INVALID_URLS_RECORDED = 1000;

    private Map<String, AtomicInteger> invalidUrls;

    public void reportInvalidUrl(@NotNull String url) {
        if (invalidUrls.containsKey(url)) {
            invalidUrls.get(url).incrementAndGet();
        } else {
            invalidUrls.put(url, new AtomicInteger(1));
        }
    }

    public Map<String, AtomicInteger> getInvalidUrls() {
        synchronized (invalidUrls) {
            return sortByNumericValue(invalidUrls);
        }
    }

    @Activate
    private void activate(Configuration configuration) {
        invalidUrls = Collections.synchronizedMap(new FixedSizeMap<>(configuration.maxNumberOfInvalidUrlsRecorded()));
    }

    private static <K, V extends Comparable<? super V>> Map<K, V> sortByComparableValue(Map<K, V> map) {
        List<Map.Entry<K, V>> list = new ArrayList<>(map.entrySet());
        list.sort(Map.Entry.comparingByValue());

        Map<K, V> result = new LinkedHashMap<>();
        for (Map.Entry<K, V> entry : list) {
            result.put(entry.getKey(), entry.getValue());
        }
        return result;
    }

    private static <K, V extends Number> Map<K, V> sortByNumericValue(Map<K, V> map) {
        List<Map.Entry<K, V>> list = new ArrayList<>(map.entrySet());
        list.sort((left, right) -> {
            double leftNumber = left.getValue().doubleValue();
            double rightNumber = right.getValue().doubleValue();
            if (leftNumber < rightNumber) {
                return -1;
            } else if (leftNumber > rightNumber) {
                return 1;
            }
            return 0;
        });

        Map<K, V> result = new LinkedHashMap<>();
        for (Map.Entry<K, V> entry : list) {
            result.put(entry.getKey(), entry.getValue());
        }
        return result;
    }
}
