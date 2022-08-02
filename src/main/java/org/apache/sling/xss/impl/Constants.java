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
package org.apache.sling.xss.impl;

import java.util.Arrays;
import java.util.List;

public class Constants {
    static final String REMOVE_TAG_STRING = "removeTag";
    public static final String REMOVE_ATTRIBUTE_STRING = "removeAttribute";
    static final String ALLOW_DYNAMIC_ATTRIBUTES_STRING = "allowDynamicAttributes";
    static final String TRUNCATE = "truncate";
    static final String FILTER = "filter";
    static final String REMOVE = "remove";
    static final String VALIDATE = "validate";
    
    public static final List<String> ALLOWED_EMPTY_TAGS = Arrays.asList(
        "br",
        "hr",
        "a",
        "img",
        "link",
        "iframe",
        "script",
        "object",
        "applet",
        "frame",
        "base",
        "param",
        "meta",
        "input",
        "textarea",
        "embed",
        "basefont",
        "col"
      );

}
