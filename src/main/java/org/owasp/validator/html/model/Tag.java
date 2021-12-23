package org.owasp.validator.html.model;

import java.util.HashMap;
import java.util.Map;

public class Tag {

    private final String name;
    private final Map<String, Attribute> tagAttributes;
    private final String action;

    public Tag(String name, Map<String, Attribute> tagAttributes, String action) {
        this.name = name;
        this.tagAttributes = tagAttributes;
        this.action = action;
    }

    public Attribute getAttributeByName(String href) {
        return tagAttributes.get(href);
    }

    public String getAction() {
        throw new IllegalStateException();
    }

    public boolean isAction(String action) {
        throw new IllegalStateException();
    }

    public Tag mutateAction(String action) {
        return new Tag(name, tagAttributes, action);
    }

    public String getRegularExpression() {
        throw new IllegalStateException();
    }

    public String getName() {
        throw new IllegalStateException();
    }
}
