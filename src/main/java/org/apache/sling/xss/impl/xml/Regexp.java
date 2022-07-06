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

import java.util.regex.Pattern;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;

public class Regexp {
    private String name;
    private String value;

    @JsonCreator
    public Regexp(@JacksonXmlProperty(localName = "name", isAttribute = true) String name,
            @JacksonXmlProperty(localName = "value", isAttribute = true) String regexp) {

        this.name = name;
        this.value = regexp;
    }

    public String getName() {
        return name;
    }

    public String getValue() {
        return value;
    }

    public Pattern getPattern() {
        return Pattern.compile(value);
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof Regexp) {
            return ((Regexp) obj).name == name || ((Regexp) obj).name.equals(name)
                    && ((Regexp) obj).value == value
                    || ((Regexp) obj).value.equals(value);
        }
        return false;
    }

    @Override
    public int hashCode() {
        return name.hashCode() + value.hashCode();
    }
}
