package org.owasp.validator.html.model;

import java.util.List;
import java.util.regex.Pattern;

public class Attribute {

    private final String name;
    private final List<Pattern> allowedRegexps;
    private final List<String> allowedValues;
    private final String onInvalidStr;
    private final String description;

    public Attribute(String name, List<Pattern> allowedRegexps, List<String> allowedValues, String onInvalidStr, String description) {
        this.name = name;
        this.allowedRegexps = allowedRegexps;
        this.allowedValues = allowedValues;
        this.onInvalidStr = onInvalidStr;
        this.description = description;
    }

    public boolean matchesAllowedExpression(String value){
        String input = value.toLowerCase();
        for (Pattern pattern : allowedRegexps) {
            if (pattern != null && pattern.matcher(input).matches()) {
                return true;
            }
        }
        return false;
    }

    public boolean containsAllowedValue(String valueInLowerCase){
        return allowedValues.contains(valueInLowerCase);
    }

    public Attribute mutate(String onInvalid, String description) {
        return new Attribute(name, allowedRegexps, allowedValues, onInvalidStr, description);
    }
}
