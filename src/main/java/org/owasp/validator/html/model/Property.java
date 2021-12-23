package org.owasp.validator.html.model;

import java.util.List;
import java.util.regex.Pattern;

public class Property {
    private final String name;
    private final List<Pattern> allowedRegexp3;
    private final List<String> allowedValue;
    private final List<String> shortHandRefs;
    private final String description;
    private final String onInvalidStr;

    public Property(String name, List<Pattern> allowedRegexp3, List<String> allowedValue, List<String> shortHandRefs, String description, String onInvalidStr) {
        this.name = name;
        this.allowedRegexp3 = allowedRegexp3;
        this.allowedValue = allowedValue;
        this.shortHandRefs = shortHandRefs;
        this.description = description;
        this.onInvalidStr = onInvalidStr;
    }
}
