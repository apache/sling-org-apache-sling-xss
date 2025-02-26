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

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

import java.io.IOException;
import java.io.InputStream;

import com.fasterxml.jackson.dataformat.xml.XmlMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AntiSamyXmlParser {

    private static final String DIRECTIVE_EMBED_STYLE_SHEETS = "embedStyleSheets";

    private final Logger logger = LoggerFactory.getLogger(getClass());

    public AntiSamyRules createRules(InputStream input) throws XMLStreamException, IOException {

        XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance();
        // disable external entities declarations
        xmlInputFactory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, Boolean.FALSE);

        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(input);
        XmlMapper mapper = new XmlMapper(xmlInputFactory, XMLOutputFactory.newInstance());
        AntiSamyRules rules = mapper.readValue(xmlStreamReader, AntiSamyRules.class);
        if ("true".equals(rules.getDirectivesByName().get(DIRECTIVE_EMBED_STYLE_SHEETS))) {
            logger.warn(
                    "Unsupported configuration directive {} is set to true and will be ignored",
                    DIRECTIVE_EMBED_STYLE_SHEETS);
        }
        xmlStreamReader.close();
        return rules;
    }
}
