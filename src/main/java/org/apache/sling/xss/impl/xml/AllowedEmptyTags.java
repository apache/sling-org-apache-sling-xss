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
package org.apache.sling.xss.impl.xml;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlElementWrapper;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;

public class AllowedEmptyTags {

    @JacksonXmlElementWrapper(localName = "literal-list")
    @JacksonXmlProperty(localName = "literal")
    private List<Literal> allowedEmptyTagsList = Collections.emptyList();

    public List<Literal> getLiteralList() {
        return allowedEmptyTagsList;
    }

    public List<String> getLiterals() {
        // reads out the literals and creates a list out of it
        return allowedEmptyTagsList.stream().map(Literal::getValue).collect(Collectors.toList());
    }
}
