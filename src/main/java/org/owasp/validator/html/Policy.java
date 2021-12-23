package org.owasp.validator.html;

import org.owasp.validator.html.model.Attribute;
import org.owasp.validator.html.model.Property;
import org.owasp.validator.html.model.Tag;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.ErrorHandler;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static org.owasp.validator.html.util.XMLUtil.getAttributeValue;

public class Policy {
    private static final String POLICY_SCHEMA_URI = "antisamy.xsd";

    protected final Map<String, Pattern> commonRegularExpressions = new HashMap<>();
    protected final Map<String, Attribute> commonAttributes = new HashMap<>();
    protected final Map<String, Tag> tagRules = new HashMap<>();
    protected final Map<String, Property> cssRules = new HashMap<>();
    protected final Map<String, String> directives = new HashMap<>();
    protected final Map<String, Attribute> globalAttributes = new HashMap<>();
    protected final Map<String, Attribute> dynamicAttributes = new HashMap<>();
    protected final List<String> allowedEmptyTags = new ArrayList<>();
    protected final List<String> requireClosingTags = new ArrayList<>();

    protected Policy(InputStream input) throws PolicyException {
        Element root = getTopLevelElement(input);
        init(root);
    }

    public static Policy getInstance(InputStream bais) throws PolicyException {
        return new Policy(bais);
    }

    public Tag getTagByLowercaseName(String a) {
        return tagRules.get(a);
    }

    private Element getTopLevelElement(InputStream input) throws PolicyException {
        ClassLoader tccl = Thread.currentThread().getContextClassLoader();
        try {
            Thread.currentThread().setContextClassLoader(Policy.class.getClassLoader());

            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            dbf.setNamespaceAware(true);
            InputStream schemaStream = Policy.class.getClassLoader().getResourceAsStream(POLICY_SCHEMA_URI);
            Source schemaSource = new StreamSource(schemaStream);
            Schema schema = null;
            try {
                schema = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI)
                        .newSchema(schemaSource);
            } catch (SAXException e) {
                throw new PolicyException(e);
            }
            dbf.setSchema(schema);
            DocumentBuilder db = dbf.newDocumentBuilder();
            db.setErrorHandler(new SAXErrorHandler());
            Document dom = db.parse(new InputSource(input));

            Element element = dom.getDocumentElement();
            return element;
        } catch (Exception e) {
            throw new PolicyException(e);
        } finally {
            Thread.currentThread().setContextClassLoader(tccl);
        }
    }

    private void init(Element topLevelElement) throws PolicyException {
        parseCommonRegExps(getFirstChild(topLevelElement, "common-regexps"), commonRegularExpressions);
        parseDirectives(getFirstChild(topLevelElement, "directives"), directives);
        parseCommonAttributes(getFirstChild(topLevelElement, "common-attributes"), commonAttributes, commonRegularExpressions);
        parseGlobalAttributes(getFirstChild(topLevelElement, "global-tag-attributes"), globalAttributes, commonAttributes);
        parseDynamicAttributes(getFirstChild(topLevelElement, "dynamic-tag-attributes"), dynamicAttributes, commonAttributes);
        parseTagRules(getFirstChild(topLevelElement, "tag-rules"), commonAttributes, commonRegularExpressions, tagRules);
        parseCSSRules(getFirstChild(topLevelElement, "css-rules"), cssRules, commonRegularExpressions);

        parseAllowedEmptyTags(getFirstChild(topLevelElement, "allowed-empty-tags"), allowedEmptyTags);
        parseRequireClosingTags(getFirstChild(topLevelElement, "require-closing-tags"), requireClosingTags);
    }

    /**
     * Go through <directives> section of the policy file.
     *
     * @param root       Top level of <directives>
     * @param directives The directives map to update
     */
    private static void parseDirectives(Element root, Map<String, String> directives) {
        for (Element ele : getByTagName(root, "directive")) {
            String name = getAttributeValue(ele, "name");
            String value = getAttributeValue(ele, "value");
            directives.put(name, value);
        }
    }

    /**
     * Go through <allowed-empty-tags> section of the policy file.
     *
     * @param allowedEmptyTagsListNode Top level of <allowed-empty-tags>
     * @param allowedEmptyTags         The tags that can be empty
     */
    private static void parseAllowedEmptyTags(Element allowedEmptyTagsListNode,
                                              List<String> allowedEmptyTags) throws PolicyException {
        if (allowedEmptyTagsListNode != null) {
            for (Element literalNode :
                    getGrandChildrenByTagName(allowedEmptyTagsListNode, "literal-list", "literal")) {

                String value = getAttributeValue(literalNode, "value");
                if (value != null && value.length() > 0) {
                    allowedEmptyTags.add(value);
                }
            }
        } else allowedEmptyTags.addAll(Arrays.asList(
                "br", "hr", "a", "img", "link", "iframe", "script", "object", "applet",
                "frame", "base", "param", "meta", "input", "textarea", "embed",
                "basefont", "col"));
    }

    /**
     * Go through <require-closing-tags> section of the policy file.
     *
     * @param requireClosingTagsListNode Top level of <require-closing-tags>
     * @param requireClosingTags         The list of tags that require closing
     */
    private static void parseRequireClosingTags(Element requireClosingTagsListNode,
                                                List<String> requireClosingTags) throws PolicyException {
        if (requireClosingTagsListNode != null) {
            for (Element literalNode :
                    getGrandChildrenByTagName(requireClosingTagsListNode, "literal-list", "literal")) {

                String value = getAttributeValue(literalNode, "value");
                if (value != null && value.length() > 0) {
                    requireClosingTags.add(value);
                }
            }
        } else requireClosingTags.addAll(Arrays.asList(
                "iframe", "script", "link"
        ));
    }

    /**
     * Go through <global-tag-attributes> section of the policy file.
     *
     * @param root              Top level of <global-tag-attributes>
     * @param globalAttributes1 A HashMap of global Attributes that need validation for every tag.
     * @param commonAttributes  The common attributes
     * @throws PolicyException
     */
    private static void parseGlobalAttributes(Element root, Map<String, Attribute> globalAttributes1, Map<String, Attribute> commonAttributes) throws PolicyException {
        for (Element ele : getByTagName(root, "attribute")) {

            String name = getAttributeValue(ele, "name");
            Attribute toAdd = commonAttributes.get(name.toLowerCase());

            if (toAdd != null) globalAttributes1.put(name.toLowerCase(), toAdd);
            else throw new PolicyException("Global attribute '" + name
                    + "' was not defined in <common-attributes>");
        }
    }

    /**
     * Go through <dynamic-tag-attributes> section of the policy file.
     *
     * @param root              Top level of <dynamic-tag-attributes>
     * @param dynamicAttributes A HashMap of dynamic Attributes that need validation for every tag.
     * @param commonAttributes  The common attributes
     * @throws PolicyException
     */
    private static void parseDynamicAttributes(Element root, Map<String, Attribute> dynamicAttributes, Map<String, Attribute> commonAttributes) throws PolicyException {
        for (Element ele : getByTagName(root, "attribute")) {

            String name = getAttributeValue(ele, "name");
            Attribute toAdd = commonAttributes.get(name.toLowerCase());

            if (toAdd != null) {
                String attrName = name.toLowerCase().substring(0, name.length() - 1);
                dynamicAttributes.put(attrName, toAdd);
            } else throw new PolicyException("Dynamic attribute '" + name
                    + "' was not defined in <common-attributes>");
        }
    }

    /**
     * Go through the <common-regexps> section of the policy file.
     *
     * @param root                      Top level of <common-regexps>
     * @param commonRegularExpressions1 the antisamy pattern objects
     */
    private static void parseCommonRegExps(Element root, Map<String, Pattern> commonRegularExpressions1) {
        for (Element ele : getByTagName(root, "regexp")) {

            String name = getAttributeValue(ele, "name");
            Pattern pattern = Pattern.compile(getAttributeValue(ele, "value"), Pattern.DOTALL);
            commonRegularExpressions1.put(name, pattern);
        }
    }

    private static void parseCommonAttributes(Element root, Map<String, Attribute> commonAttributes1,
                                              Map<String, Pattern> commonRegularExpressions1) {

        for (Element ele : getByTagName(root, "attribute")) {
            String onInvalid = getAttributeValue(ele, "onInvalid");
            String name = getAttributeValue(ele, "name");

            List<Pattern> allowedRegexps = getAllowedRegexps(commonRegularExpressions1, ele);
            List<String> allowedValues = getAllowedLiterals(ele);

            final String onInvalidStr;
            if (onInvalid != null && onInvalid.length() > 0) {
                onInvalidStr = onInvalid;
            } else onInvalidStr =  "removeAttribute";

            String description = getAttributeValue(ele, "description");
            Attribute attribute = new Attribute(getAttributeValue(ele, "name"), allowedRegexps,
                    allowedValues, onInvalidStr, description);
            commonAttributes1.put(name.toLowerCase(), attribute);
        }
    }

    private static List<String> getAllowedLiterals(Element ele) {
        List<String> allowedValues = new ArrayList<String>();
        for (Element literalNode : getGrandChildrenByTagName(ele, "literal-list", "literal")) {
            String value = getAttributeValue(literalNode, "value");

            if (value != null && value.length() > 0) {
                allowedValues.add(value);
            } else if (literalNode.getNodeValue() != null) {
                allowedValues.add(literalNode.getNodeValue());
            }
        }
        return allowedValues;
    }

    private static List<Pattern> getAllowedRegexps(Map<String, Pattern> commonRegularExpressions1, Element ele) {
        List<Pattern> allowedRegExp = new ArrayList<Pattern>();
        for (Element regExpNode : getGrandChildrenByTagName(ele, "regexp-list", "regexp")) {
            String regExpName = getAttributeValue(regExpNode, "name");
            String value = getAttributeValue(regExpNode, "value");

            if (regExpName != null && regExpName.length() > 0) {
                allowedRegExp.add(commonRegularExpressions1.get(regExpName));
            } else allowedRegExp.add(Pattern.compile(value, Pattern.DOTALL));
        }
        return allowedRegExp;
    }

    private static List<Pattern> getAllowedRegexps2(Map<String, Pattern> commonRegularExpressions1,
                                                    Element attributeNode, String tagName) throws PolicyException {
        List<Pattern> allowedRegexps = new ArrayList<Pattern>();
        for (Element regExpNode : getGrandChildrenByTagName(attributeNode, "regexp-list", "regexp")) {
            String regExpName = getAttributeValue(regExpNode, "name");
            String value = getAttributeValue(regExpNode, "value");

            /*
             * Look up common regular expression specified
             * by the "name" field. They can put a common
             * name in the "name" field or provide a custom
             * value in the "value" field. They must choose
             * one or the other, not both.
             */
            if (regExpName != null && regExpName.length() > 0) {
                Pattern pattern = commonRegularExpressions1.get(regExpName);
                if (pattern != null) {
                    allowedRegexps.add(pattern);
                } else throw new PolicyException("Regular expression '" + regExpName +
                        "' was referenced as a common regexp in definition of '" + tagName +
                        "', but does not exist in <common-regexp>");
            } else if (value != null && value.length() > 0) {
                allowedRegexps.add(Pattern.compile(value, Pattern.DOTALL));
            }
        }
        return allowedRegexps;
    }

    private static List<Pattern> getAllowedRegexp3(Map<String, Pattern> commonRegularExpressions1,
                                                   Element ele, String name) throws PolicyException {

        List<Pattern> allowedRegExp = new ArrayList<Pattern>();
        for (Element regExpNode : getGrandChildrenByTagName(ele, "regexp-list", "regexp")) {
            String regExpName = getAttributeValue(regExpNode, "name");
            String value = getAttributeValue(regExpNode, "value");

            Pattern pattern = commonRegularExpressions1.get(regExpName);

            if (pattern != null) {
                allowedRegExp.add(pattern);
            } else if (value != null) {
                allowedRegExp.add(Pattern.compile(value, Pattern.DOTALL));
            } else throw new PolicyException("Regular expression '" + regExpName +
                    "' was referenced as a common regexp in definition of '" + name +
                    "', but does not exist in <common-regexp>");
        }
        return allowedRegExp;
    }

    private static void parseTagRules(Element root, Map<String, Attribute> commonAttributes1, Map<String,
            Pattern> commonRegularExpressions1, Map<String, Tag> tagRules1) throws PolicyException {

        if (root == null) return;

        for (Element tagNode : getByTagName(root, "tag")) {
            String name = getAttributeValue(tagNode, "name");
            String action = getAttributeValue(tagNode, "action");

            NodeList attributeList = tagNode.getElementsByTagName("attribute");
            Map<String, Attribute> tagAttributes = getTagAttributes(commonAttributes1, commonRegularExpressions1, attributeList, name);
            Tag tag = new Tag(name, tagAttributes, action);

            tagRules1.put(name.toLowerCase(), tag);
        }
    }

    private static Map<String, Attribute> getTagAttributes(Map<String, Attribute> commonAttributes1, Map<String,
            Pattern> commonRegularExpressions1, NodeList attributeList, String tagName) throws PolicyException {

        Map<String,Attribute> tagAttributes = new HashMap<String, Attribute>();
        for (int j = 0; j < attributeList.getLength(); j++) {
            Element attributeNode = (Element) attributeList.item(j);

            String attrName = getAttributeValue(attributeNode, "name").toLowerCase();
            if (!attributeNode.hasChildNodes()) {
                Attribute attribute = commonAttributes1.get(attrName);

                // All they provided was the name, so they must want a common attribute.
                if (attribute != null) {
                    /*
                     * If they provide onInvalid/description values here they will
                     * override the common values.
                     */

                    String onInvalid = getAttributeValue(attributeNode, "onInvalid");
                    String description = getAttributeValue(attributeNode, "description");
                    Attribute changed = attribute.mutate(onInvalid, description);
                    commonAttributes1.put(attrName, changed);
                    tagAttributes.put(attrName, changed);

                } else throw new PolicyException("Attribute '" + getAttributeValue(attributeNode, "name") +
                        "' was referenced as a common attribute in definition of '" + tagName +
                        "', but does not exist in <common-attributes>");

            } else {
                List<Pattern> allowedRegexps2 = getAllowedRegexps2(commonRegularExpressions1, attributeNode, tagName);
                List<String> allowedValues2 = getAllowedLiterals(attributeNode);
                String onInvalid = getAttributeValue(attributeNode, "onInvalid");
                String description = getAttributeValue(attributeNode, "description");
                Attribute attribute = new Attribute(getAttributeValue(attributeNode, "name"), allowedRegexps2, allowedValues2, onInvalid, description);

                // Add fully built attribute.
                tagAttributes.put(attrName, attribute);
            }
        }
        return tagAttributes;
    }

    private static void parseCSSRules(Element root, Map<String, Property> cssRules1, Map<String, Pattern> commonRegularExpressions1) throws PolicyException {

        for (Element ele : getByTagName(root, "property")) {
            String name = getAttributeValue(ele, "name");
            String description = getAttributeValue(ele, "description");

            List<Pattern> allowedRegexp3 = getAllowedRegexp3(commonRegularExpressions1, ele, name);

            List<String> allowedValue = new ArrayList<String>();
            for (Element literalNode : getGrandChildrenByTagName(ele, "literal-list", "literal")) {
                allowedValue.add(getAttributeValue(literalNode, "value"));
            }

            List<String> shortHandRefs = new ArrayList<String>();
            for (Element shorthandNode : getGrandChildrenByTagName(ele, "shorthand-list", "shorthand")) {
                shortHandRefs.add(getAttributeValue(shorthandNode, "name"));
            }

            String onInvalid = getAttributeValue(ele, "onInvalid");
            final String onInvalidStr;
            if (onInvalid != null && onInvalid.length() > 0) {
                onInvalidStr = onInvalid;
            } else onInvalidStr =  "removeAttribute";

            Property property = new Property(name,allowedRegexp3, allowedValue, shortHandRefs, description, onInvalidStr);
            cssRules1.put(name.toLowerCase(), property);
        }
    }

    private static Element getFirstChild(Element element, String tagName) {
        if (element == null) return null;
        NodeList elementsByTagName = element.getElementsByTagName(tagName);
        if (elementsByTagName != null && elementsByTagName.getLength() > 0)
            return (Element) elementsByTagName.item(0);
        else return null;
    }

    private static Iterable<Element>  getGrandChildrenByTagName(Element parent, String immediateChildName, String subChild){
        NodeList elementsByTagName = parent.getElementsByTagName(immediateChildName);
        if (elementsByTagName.getLength() == 0) return Collections.emptyList();
        Element regExpListNode = (Element) elementsByTagName.item(0);
        return getByTagName( regExpListNode, subChild);
    }

    private static Iterable<Element> getByTagName(Element parent, String tagName) {
        if (parent == null) return Collections.emptyList();

        final NodeList nodes = parent.getElementsByTagName(tagName);
        return new Iterable<Element>() {
            public Iterator<Element> iterator() {
                return new Iterator<Element>() {
                    int pos = 0;
                    int len = nodes.getLength();

                    public boolean hasNext() {
                        return pos < len;
                    }

                    public Element next() {
                        return (Element) nodes.item(pos++);
                    }

                    public void remove() {
                        throw new UnsupportedOperationException("Cant remove");
                    }
                };
            }
        };
    }

    static class SAXErrorHandler implements ErrorHandler {
        @Override
        public void error(SAXParseException arg0) throws SAXException {
            throw arg0;
        }

        @Override
        public void fatalError(SAXParseException arg0) throws SAXException {
            throw arg0;
        }

        @Override
        public void warning(SAXParseException arg0) throws SAXException {
            throw arg0;
        }
    }
}
