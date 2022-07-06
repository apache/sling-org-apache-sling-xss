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
package org.apache.sling.xss.impl.style;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.StringJoiner;
import java.util.stream.Collectors;

import org.apache.sling.xss.impl.xml.Policy.CssPolicy;
import org.apache.sling.xss.impl.xml.Property;
import org.w3c.css.sac.CSSException;
import org.w3c.css.sac.CombinatorCondition;
import org.w3c.css.sac.Condition;
import org.w3c.css.sac.ConditionalSelector;
import org.w3c.css.sac.DescendantSelector;
import org.w3c.css.sac.DocumentHandler;
import org.w3c.css.sac.InputSource;
import org.w3c.css.sac.LexicalUnit;
import org.w3c.css.sac.NegativeCondition;
import org.w3c.css.sac.SACMediaList;
import org.w3c.css.sac.Selector;
import org.w3c.css.sac.SelectorList;
import org.w3c.css.sac.SiblingSelector;

public class ValidatingDocumentHandler implements DocumentHandler {

    private final CssPolicy cssPolicy;
    private final StringBuilder cleanCss = new StringBuilder();
    private final boolean inline;

    private boolean inSelector;

    public ValidatingDocumentHandler(CssPolicy cssPolicy, boolean inline) {
        this.cssPolicy = cssPolicy;
        this.inline = inline;
    }

    @Override
    public void startSelector(SelectorList selectors) throws CSSException {

        List<String> validSelectors = validateSelectors(selectors);
        if ( validSelectors.isEmpty() )
            return;

        StringJoiner joiner = new StringJoiner(", ", "", " {\n");
        validSelectors.forEach( joiner::add );
        cleanCss.append(joiner.toString());
        inSelector = true;
    }

    @Override
    public void endSelector(SelectorList selectors) throws CSSException {
        if ( !inSelector )
            return;

        cleanCss.append("}\n");
        inSelector = false;
    }

    @Override
    public void property(String name, LexicalUnit value, boolean important) throws CSSException {
        if (!inSelector && !inline) {
            return;
        }

        List<String> validPropertyValues = validatePropertyValues(name, value);
        if ( validPropertyValues.isEmpty() )
            return;

        cleanCss.append(validPropertyValues.stream()
            .map( s -> important  ? s + " !important" : s)
            .collect(Collectors.joining(" ", "\t" + name + ": ", ";\n")));
    }

    private List<String> validateSelectors(SelectorList selectors) {
        List<String> selectorNames = new ArrayList<>();
        for ( int i = 0 ; i < selectors.getLength(); i++ ) {
            Selector selector = selectors.item(i);
            if ( isValidSelector(selector) )
                selectorNames.add(selector.toString());
        }
        return selectorNames;
    }

    private boolean isValidSelector(Selector selector) {
        switch ( selector.getSelectorType() ) {
        case Selector.SAC_ANY_NODE_SELECTOR:
        case Selector.SAC_ELEMENT_NODE_SELECTOR:
        case Selector.SAC_PSEUDO_ELEMENT_SELECTOR:
        case Selector.SAC_ROOT_NODE_SELECTOR:
        case Selector.SAC_NEGATIVE_SELECTOR:
            return cssPolicy.isValidElementName(selector.toString().toLowerCase(Locale.ENGLISH));
        case Selector.SAC_DIRECT_ADJACENT_SELECTOR:
            SiblingSelector sibling = (SiblingSelector) selector;
            return isValidSelector(sibling.getSiblingSelector()) && isValidSelector(sibling.getSelector());
        case Selector.SAC_CONDITIONAL_SELECTOR:
            ConditionalSelector conditional = (ConditionalSelector) selector;
            return isValidSelector(conditional.getSimpleSelector()) && isValidCondition(conditional.getCondition());
        case Selector.SAC_CHILD_SELECTOR:
        case Selector.SAC_DESCENDANT_SELECTOR:
            DescendantSelector descendant = (DescendantSelector) selector;
            return isValidSelector(descendant.getAncestorSelector()) && isValidSelector(descendant.getSimpleSelector());
            default:
                return false;
        }
    }

    private boolean isValidCondition(Condition condition) {

        switch (condition.getConditionType()) {
        case Condition.SAC_CLASS_CONDITION:
            return cssPolicy.isValidClassName(condition.toString().toLowerCase(Locale.ENGLISH));
        case Condition.SAC_ID_CONDITION:
            return cssPolicy.isValidId(condition.toString().toLowerCase(Locale.ENGLISH));
        case Condition.SAC_AND_CONDITION:
        case Condition.SAC_OR_CONDITION:
            CombinatorCondition comb = (CombinatorCondition) condition;
            return isValidCondition(comb.getFirstCondition()) && isValidCondition(comb.getSecondCondition());
        case Condition.SAC_NEGATIVE_CONDITION:
            return isValidCondition(((NegativeCondition) condition).getCondition());
        case Condition.SAC_PSEUDO_CLASS_CONDITION:
            return cssPolicy.isValidPseudoElementName(condition.toString().toLowerCase(Locale.ENGLISH));
        case Condition.SAC_ATTRIBUTE_CONDITION:
        case Condition.SAC_BEGIN_HYPHEN_ATTRIBUTE_CONDITION:
        case Condition.SAC_ONE_OF_ATTRIBUTE_CONDITION:
            return false;
        case Condition.SAC_ONLY_CHILD_CONDITION:
        case Condition.SAC_ONLY_TYPE_CONDITION:
            // constant values, unconditionally true
            return true;
        default:
            return false;
        }
    }

    private List<String> validatePropertyValues(String name, LexicalUnit value) {
        List<String> validPropertyValues = new ArrayList<>();
        while ( value != null ) {
            String stringValue = lexicalValueToString(value);
            value = value.getNextLexicalUnit();
            boolean isValid = validateProperty(name, stringValue);
            if ( !isValid )
                continue;
            validPropertyValues.add(stringValue);
        }
        return validPropertyValues;
    }

    public String getValidCss() {
        return cleanCss.toString();
    }

    private boolean validateProperty(String name, String lexicalValueToString) {
        if ( lexicalValueToString == null )
            return false;

        Property property = cssPolicy.getCssRules().get(name);
        if ( property == null )
            return false;

        if ( property.getLiterals().contains(lexicalValueToString) )
            return true;

        if ( property.getRegexps().stream()
            .anyMatch( p -> p.matcher(lexicalValueToString).matches() ) )
            return true;

        if ( property.getShorthands().stream()
            .anyMatch( s -> validateProperty(s, lexicalValueToString)) )
            return true;

        return false;
    }

    private String lexicalValueToString(LexicalUnit lu) {
        switch (lu.getLexicalUnitType()) {
        case LexicalUnit.SAC_PERCENTAGE:
        case LexicalUnit.SAC_DIMENSION:
        case LexicalUnit.SAC_EM:
        case LexicalUnit.SAC_EX:
        case LexicalUnit.SAC_PIXEL:
        case LexicalUnit.SAC_INCH:
        case LexicalUnit.SAC_CENTIMETER:
        case LexicalUnit.SAC_MILLIMETER:
        case LexicalUnit.SAC_POINT:
        case LexicalUnit.SAC_PICA:
        case LexicalUnit.SAC_DEGREE:
        case LexicalUnit.SAC_GRADIAN:
        case LexicalUnit.SAC_RADIAN:
        case LexicalUnit.SAC_MILLISECOND:
        case LexicalUnit.SAC_SECOND:
        case LexicalUnit.SAC_HERTZ:
        case LexicalUnit.SAC_KILOHERTZ:
            // various measurements
            return lu.getFloatValue() + lu.getDimensionUnitText();
        case LexicalUnit.SAC_INTEGER:
            // number
            return String.valueOf(lu.getIntegerValue());
        case LexicalUnit.SAC_REAL:
            // number
            return String.valueOf(lu.getFloatValue());
        case LexicalUnit.SAC_STRING_VALUE:
        case LexicalUnit.SAC_IDENT:
            // identifier, potentially needs quoting
            String stringValue = lu.getStringValue();
            if (stringValue.indexOf(" ") != -1)
                stringValue = "\"" + stringValue + "\"";
            return stringValue;
        case LexicalUnit.SAC_URI:
            // this is a URL
            return "url(" + lu.getStringValue() + ")";
        case LexicalUnit.SAC_RGBCOLOR:
            // this is a rgb encoded color; technically we don't need to encode
            // it precisely like this but it makes it simpler to keep the tests
            // based on the AntiSamy implementation
            return toRgbString(lu);
        case LexicalUnit.SAC_INHERIT:
            // constant
            return "inherit";
        case LexicalUnit.SAC_OPERATOR_COMMA:
            return ",";
        case LexicalUnit.SAC_ATTR:
        case LexicalUnit.SAC_COUNTER_FUNCTION:
        case LexicalUnit.SAC_COUNTERS_FUNCTION:
        case LexicalUnit.SAC_FUNCTION:
        case LexicalUnit.SAC_RECT_FUNCTION:
        case LexicalUnit.SAC_SUB_EXPRESSION:
        case LexicalUnit.SAC_UNICODERANGE:
        default:
            // unsupported
            return null;
        }
    }

    private String toRgbString(LexicalUnit lu) {
        // 16 default capacity actually fits nicely
        //
        // rgb(255,255,255)
        // ....|....|....|.
        StringBuilder sb = new StringBuilder();
        LexicalUnit param = lu.getParameters();
        sb.append("rgb(");
        sb.append(param.getIntegerValue()); // R value
        sb.append(',');
        param = param.getNextLexicalUnit(); // comma
        param = param.getNextLexicalUnit(); // G value
        sb.append(param.getIntegerValue());
        sb.append(',');
        param = param.getNextLexicalUnit(); // comma
        param = param.getNextLexicalUnit(); // B value
        sb.append(param.getIntegerValue());
        sb.append(')');

        return sb.toString();
    }

    @Override
    public void importStyle(String uri, SACMediaList media, String defaultNamespaceURI) throws CSSException {
        // embedded stylesheets are not supported
    }

    @Override
    public void startDocument(InputSource source) throws CSSException {
        // nothing to do
    }

    @Override
    public void endDocument(InputSource source) throws CSSException {
        // nothing to do
    }

    @Override
    public void comment(String text) throws CSSException {
        // we intentionally ignore comments, they don't need to be in the output
    }

    @Override
    public void ignorableAtRule(String atRule) throws CSSException {
        // nothing to do

    }

    @Override
    public void namespaceDeclaration(String prefix, String uri) throws CSSException {
        // nothing to do

    }

    @Override
    public void startMedia(SACMediaList media) throws CSSException {
        // nothing to do

    }

    @Override
    public void endMedia(SACMediaList media) throws CSSException {
        // nothing to do

    }

    @Override
    public void startPage(String name, String pseudo_page) throws CSSException {
        // nothing to do

    }

    @Override
    public void endPage(String name, String pseudo_page) throws CSSException {
        // nothing to do
    }

    @Override
    public void startFontFace() throws CSSException {
        // nothing to do

    }

    @Override
    public void endFontFace() throws CSSException {
        // nothing to do

    }

}
