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

import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlElementWrapper;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;

public class Attribute {

    private String name;
    private String description;
    private String onInvalid;

    @JacksonXmlElementWrapper(localName = "regexp-list")
    private List<Regexp> regexpList;

    @JacksonXmlElementWrapper(localName = "literal-list")
    private List<Literal> literalList;

    @JsonCreator
    public Attribute(@JacksonXmlProperty(localName = "name", isAttribute = true) String name,
            @JacksonXmlProperty(localName = "regexp") List<Regexp> allowedRegexps,
            @JacksonXmlProperty(localName = "literal") List<Literal> allowedValues,
            @JacksonXmlProperty(localName = "onInvalid", isAttribute = true) String onInvalid,
            @JacksonXmlProperty(localName = "description", isAttribute = true) String description) {
        this.name = name;
        this.description = description;
        this.onInvalid = onInvalid != null && onInvalid.length() > 0 ? onInvalid : "removeAttribute";
        this.regexpList = allowedRegexps;
        this.literalList = allowedValues;
    }

    @Override
    public String toString() {
        return "Attribute - name: " + name + ", description " + description + ", onInvalid " + onInvalid
                + ", allowedRegexlist: "
                + regexpList.size() + ", literals " + literalList;
    }

    public String getOnInvalid() {
        return onInvalid;
    }

    public String getDescription() {
        return description;
    }

    public String getName() {
        return name;
    }

    public List<String> getLiterals() {
        if (literalList != null && literalList.size() > 0) {
            return literalList.stream().map(literal -> literal.getValue().toLowerCase()).collect(Collectors.toList());
        }
        return null;
    }

    public List<Literal> getLiteralList() {
        return literalList;
    }

    public List<Pattern> getPatternList() {
        return regexpList.stream().map(regexp -> regexp.getPattern())
                .collect(Collectors.toList());

    }

    public List<Regexp> getRegexpList() {
        return regexpList;
    }

    public boolean containsAllowedValue(String valueInLowerCase) {
        List<String> literals = getLiterals();
        return literals != null && literals.size() > 0 ? getLiterals().contains(valueInLowerCase) : false;
    }

    public boolean matchesAllowedExpression(String value) {
        if (regexpList != null && regexpList.size() > 0) {
            for (Regexp regexp : regexpList) {
                if (regexp.getPattern() != null && regexp.getPattern().matcher(value).matches()) {
                    return true;
                }
            }
        }
        return false;
    }

    @Override
    public boolean equals(Object obj) {

        if (obj instanceof Attribute) {
            Attribute attribute = (Attribute) obj;
            return name == attribute.name || attribute.name.equals(name)
                    && description == attribute.description || attribute.description.equals(description)
                            && onInvalid == attribute.onInvalid
                    || attribute.onInvalid.equals(onInvalid)
                            && regexpList == attribute.regexpList
                    || attribute.regexpList.equals(regexpList)
                            && literalList == attribute.literalList;

        }
        return false;
    }

    @Override
    public int hashCode() {
        return name.hashCode() + description.hashCode() + onInvalid.hashCode();
    }
}
