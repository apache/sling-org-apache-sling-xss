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
import org.jetbrains.annotations.NotNull;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlElementWrapper;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;

public class Property {
    private String name;
    private String description;
    private String defaultValue;

    @JacksonXmlElementWrapper(localName = "regexp-list")
    private List<Regexp> regexpList;

    @JacksonXmlElementWrapper(localName = "literal-list")
    private List<Literal> literalList;

    @JacksonXmlElementWrapper(localName = "category-list")
    private List<Category> categoryList;

    @JacksonXmlElementWrapper(localName = "shorthand-list")
    private List<Shorthand> shorthandList;

    private String onInvalid;

    @JsonCreator
    public Property(@JacksonXmlProperty(localName = "name", isAttribute = true) String name,
            @JacksonXmlProperty(localName = "regexp") List<Regexp> allowedRegexps,
            @JacksonXmlProperty(localName = "literal") List<Literal> allowedValue,
            @JacksonXmlProperty(localName = "shorthand") List<Shorthand> shortHandRefs,
            @JacksonXmlProperty(localName = "description", isAttribute = true) String description,
            @JacksonXmlProperty(localName = "onInvalid", isAttribute = true) String onInvalidStr,
            @JacksonXmlProperty(isAttribute = true, localName = "default") String defaultValue) {

        this.name = name;
        this.description = Optional.ofNullable(description).orElse("");
        this.onInvalid = onInvalid != null && onInvalid.length() > 0 ? onInvalid : Constants.REMOVE_ATTRIBUTE_STRING;
        this.regexpList = Optional.ofNullable(allowedRegexps)
                .map(Collections::unmodifiableList)
                .orElseGet(Collections::emptyList);
        this.literalList = Optional.ofNullable(literalList)
                .map(Collections::unmodifiableList)
                .orElseGet(Collections::emptyList);
        this.shorthandList = Optional.ofNullable(shortHandRefs)
                .map(Collections::unmodifiableList)
                .orElseGet(Collections::emptyList);
        this.defaultValue = defaultValue;
    }

    public List<Category> getCategoryList() {
        return categoryList;
    }

    public String getDefaultValue() {
        return defaultValue;
    }

    public String getDescription() {
        return description;
    }

    public List<Literal> getLiteralList() {
        return literalList;
    }

    public String getName() {
        return name;
    }

    public List<Regexp> getRegexpList() {
        return regexpList;
    }

    public List<Shorthand> getShorthandList() {
        return shorthandList;
    }

    public List<String> getShorthands() {
        // reads out the shorthands and creates a list out of it
        return shorthandList.stream().map(shorthand -> shorthand.getName())
                .collect(Collectors.toList());
    }

    public List<String> getLiterals() {
        // reads out the literals and creates a list out of it
        return literalList.stream().map(literal -> literal.getValue())
                .collect(Collectors.toList());
    }

    public String getOnInvalid() {
        return onInvalid;
    }

    public List<Pattern> getRegexps() {
        // reads out the patterns and creates a list out of it
        return regexpList.stream().map(regex -> regex.getPattern())
                .collect(Collectors.toList());
    }
}
