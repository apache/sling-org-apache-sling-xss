package org.owasp.validator.html;

public class AntiSamy {
    public static final Object DOM = "DOM";
    public static final Object SAX = "SAX";

    public AntiSamy(Policy policy) {
    }

    public CleanResults scan(String input) throws ScanException {
        throw new IllegalStateException();
    }

    public CleanResults scan(String input, Object dom) {
        throw new IllegalStateException();
    }
}
