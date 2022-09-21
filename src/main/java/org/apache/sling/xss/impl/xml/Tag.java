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
package org.apache.sling.xss.impl.xml;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlElementWrapper;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;

public class Tag {
    private String name;
    private String action;
    private List<Attribute> attributeList;

    @JsonCreator
    public Tag(
            @JacksonXmlProperty(isAttribute = true, localName = "name") String name,
            @JacksonXmlProperty(isAttribute = true, localName = "action") String action,
            @JacksonXmlElementWrapper(useWrapping = false) @JacksonXmlProperty(localName = "attribute") List<Attribute> attributeList) {
        this.name = name.toLowerCase();
        this.attributeList = Optional.ofNullable(attributeList)
                .map(Collections::unmodifiableList)
                .orElseGet(Collections::emptyList);
        this.action = action.toLowerCase();

    }

    public String getAction() {
        return action;
    }

    /**
     * Indicates if the action for this tag matches the supplied action
     *
     * @param action The action to match against
     * @return True if it matches
     */
    public boolean isAction(String action) {
        return action.equals(this.action);
    }

    public Tag mutateAction(String action) {
        return new Tag(this.name, action, this.attributeList);
    }

    public List<Attribute> getAttributeList() {
        return attributeList;
    }

    public String getName() {
        return name;
    }

    public Map<String, Attribute> getAttributeMap() {
        return attributeList.stream()
                .collect(Collectors.toMap(Attribute::getName, Function.identity()));
    }

    public Attribute getAttributeByName(String name) {
        Map<String, Attribute> attributeMap = getAttributeMap();
        return attributeMap.get(name);
    }
}
