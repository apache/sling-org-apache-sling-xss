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
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlElementWrapper;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlRootElement;

@JacksonXmlRootElement(localName = "anti-samy-rules")
public class AntiSamyRules {
    @JsonIgnore
    @JacksonXmlProperty(localName = "xmlns:xsi", isAttribute = true)
    private String xmlnsXsi;

    @JsonIgnore
    @JacksonXmlProperty(localName = "noNamespaceSchemaLocation", isAttribute = true)
    private String noNamespaceSchemaLocation;

    @JacksonXmlElementWrapper(localName = "directives")
    @JacksonXmlProperty(localName = "directive")
    private List<Directive> directiveList = Collections.emptyList();

    @JacksonXmlElementWrapper(localName = "common-regexps")
    @JacksonXmlProperty(localName = "regexp")
    private List<Regexp> regexpList = Collections.emptyList();

    @JacksonXmlElementWrapper(localName = "common-attributes")
    @JacksonXmlProperty(localName = "attribute")
    private List<Attribute> commonAttributeList = Collections.emptyList();

    @JacksonXmlProperty(localName = "global-tag-attributes")
    private GlobalTagAttributes globalTagAttributes;

    @JacksonXmlProperty(localName = "dynamic-tag-attributes")
    private DynamicTagAttributes dynamicTagAttribute;

    @JacksonXmlElementWrapper(localName = "tag-rules")
    @JacksonXmlProperty(localName = "tag")
    private List<Tag> tagRulesList = Collections.emptyList();

    @JacksonXmlProperty(localName = "tags-to-encode")
    private TagsToEncode tagsToEncode;

    @JacksonXmlElementWrapper(localName = "css-rules")
    @JacksonXmlProperty(localName = "property")
    private List<Property> propertyList = Collections.emptyList();

    @JacksonXmlProperty(localName = "allowed-empty-tags")
    private AllowedEmptyTags allowedEmptyTags;

    public AllowedEmptyTags getAllowedEmptyTags() {
        return allowedEmptyTags;
    }

    public DynamicTagAttributes getDynamicTagAttribute() {
        return dynamicTagAttribute;
    }

    public GlobalTagAttributes getGlobalTagAttributes() {
        return globalTagAttributes;
    }

    public String getNoNamespaceSchemaLocation() {
        return noNamespaceSchemaLocation;
    }

    public TagsToEncode getTagsToEncode() {
        return tagsToEncode;
    }

    public String getXmlnsXsi() {
        return xmlnsXsi;
    }

    public List<Attribute> getCommonAttributeList() {
        return commonAttributeList;
    }

    public List<Directive> getDirectiveList() {
        return directiveList;
    }

    public List<Regexp> getRegexpList() {
        return regexpList;
    }

    public List<Property> getPropertyList() {
        return propertyList;
    }

    public List<Tag> getTagRulesList() {
        return tagRulesList;
    }

    public Map<String, String> getDirectivesByName() {
        Map<String, String> directivesByName = directiveList.stream()
                .collect(Collectors.toMap(Directive::getName, Directive::getValue));
        return directivesByName;
    }

    public Map<String, Pattern> getCommonPatternByName() {
        Map<String, Pattern> patternByName = regexpList.stream()
                .collect(Collectors.toMap(Regexp::getName, Regexp::getPattern));
        return patternByName;
    }
}
