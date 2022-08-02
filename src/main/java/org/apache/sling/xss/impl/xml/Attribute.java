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
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.apache.sling.xss.impl.Constants;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;
import org.jetbrains.annotations.NotNull;

public class Attribute {

    @NotNull
    private final String name;

    @NotNull
    private final String description;

    @NotNull
    private final String onInvalid;

    @NotNull
    private final List<Regexp> regexpList;

    @NotNull
    private final List<Literal> literalList;

    @JsonCreator
    public Attribute(@JacksonXmlProperty(localName = "name", isAttribute = true) @NotNull String name,
            @JacksonXmlProperty(localName = "regexp-list") List<Regexp> allowedRegexps,
            @JacksonXmlProperty(localName = "literal-list") List<Literal> literalList,
            @JacksonXmlProperty(localName = "onInvalid", isAttribute = true) String onInvalid,
            @JacksonXmlProperty(localName = "description", isAttribute = true) String description) {
        this.name = name;
        this.description = Optional.ofNullable(description).orElse("");
        this.onInvalid = onInvalid != null && onInvalid.length() > 0 ? onInvalid : Constants.REMOVE_ATTRIBUTE_STRING;
        this.regexpList = Optional.ofNullable(allowedRegexps)
                .map(Collections::unmodifiableList)
                .orElseGet(Collections::emptyList);
        this.literalList = Optional.ofNullable(literalList)
                .map(Collections::unmodifiableList)
                .orElseGet(Collections::emptyList);
    }

    @Override
    public String toString() {
        return "Attribute - name: " + name + ", description " + description + ", onInvalid " + onInvalid
                + ", allowedRegexlist: "
                + regexpList.size() + ", literals " + literalList;
    }

    @NotNull
    public String getOnInvalid() {
        return onInvalid;
    }

    @NotNull
    public String getDescription() {
        return description;
    }

    @NotNull
    public String getName() {
        return name;
    }

    @NotNull
    public List<String> getLiterals() {
        return getLiteralList().stream()
                .map(Literal::getValue)
                .map(String::toLowerCase)
                .collect(Collectors.toList());
    }

    @NotNull
    public List<Literal> getLiteralList() {
        return literalList;
    }

    @NotNull
    public List<Pattern> getPatternList() {
        return getRegexpList().stream()
                .map(Regexp::getPattern)
                .collect(Collectors.toList());
    }

    @NotNull
    public List<Regexp> getRegexpList() {
        return regexpList;
    }

    public boolean containsAllowedValue(String valueInLowerCase) {
        return getLiteralList().stream()
                .map(Literal::getValue)
                .anyMatch(valueInLowerCase::equals);
    }

    public boolean matchesAllowedExpression(String value) {
        return getPatternList().stream()
                .anyMatch(pattern -> pattern.matcher(value).matches());
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
