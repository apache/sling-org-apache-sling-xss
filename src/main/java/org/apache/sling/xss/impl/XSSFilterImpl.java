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
package org.apache.sling.xss.impl;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.io.Writer;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.Dictionary;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.regex.Pattern;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.text.StringEscapeUtils;
import org.apache.commons.text.translate.AggregateTranslator;
import org.apache.commons.text.translate.CharSequenceTranslator;
import org.apache.commons.text.translate.LookupTranslator;
import org.apache.sling.api.resource.LoginException;
import org.apache.sling.api.resource.Resource;
import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.api.resource.ResourceResolverFactory;
import org.apache.sling.api.resource.observation.ExternalResourceChangeListener;
import org.apache.sling.api.resource.observation.ResourceChange;
import org.apache.sling.api.resource.observation.ResourceChangeListener;
import org.apache.sling.serviceusermapping.ServiceUserMapped;
import org.apache.sling.xss.ProtectionContext;
import org.apache.sling.xss.XSSFilter;
import org.apache.sling.xss.impl.status.XSSStatusService;
import org.apache.sling.xss.impl.xml.Attribute;
import org.apache.sling.xss.impl.xml.Regexp;
import org.apache.sling.xss.impl.xml.Tag;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.osgi.service.component.annotations.ReferencePolicyOption;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class implements the <code>XSSFilter</code> using the Antisamy XSS protection library found at
 * <a href="http://code.google.com/p/owaspantisamy/">http://code.google.com/p/owaspantisamy/</a>.
 */
@Component(service = {XSSFilter.class})
@Designate(ocd = XSSFilterImpl.Configuration.class)
public class XSSFilterImpl implements XSSFilter {

    @ObjectClassDefinition(name = "Apache Sling XSS Filter", description = "XSS filtering utility based on AntiSamy.")
    @interface Configuration {

        @AttributeDefinition(
                name = "AntiSamy Policy Path",
                description =
                        "The path to the AntiSamy policy file (absolute or relative to the configured search paths).")
        String policyPath() default XSSFilterImpl.DEFAULT_POLICY_PATH;
    }

    private static final Logger logger = LoggerFactory.getLogger(XSSFilterImpl.class);

    public static final String ALPHA = "(?:\\p{L}\\p{M}*)";
    public static final String HEX_DIGIT = "\\p{XDigit}";
    public static final String PCT_ENCODED = "%" + HEX_DIGIT + HEX_DIGIT;
    public static final String UNRESERVED_CHARACTERS = ALPHA + "|[\\p{N}-._~]";
    public static final String SUB_DELIMS = "[!$&'()*+,;=]";
    public static final String REG_NAME =
            "(?:(?:" + UNRESERVED_CHARACTERS + ")*|(?:" + PCT_ENCODED + ")*|" + "(?:" + SUB_DELIMS + ")*)";
    public static final String PCHAR = UNRESERVED_CHARACTERS + "|" + PCT_ENCODED + "|" + SUB_DELIMS + "|:|@";
    public static final String DEC_OCTET =
            "(?:\\p{N}|[\\x31-\\x39]\\p{N}|1\\p{N}{2}|2[\\x30-\\x34]\\p{N}|25[\\x30-\\x35])";
    public static final String H16 = HEX_DIGIT + "{1,4}";
    public static final String IPv4_ADDRESS = DEC_OCTET + "\\." + DEC_OCTET + "\\." + DEC_OCTET + "\\." + DEC_OCTET;
    public static final String LS32 = "(?:" + H16 + ":" + H16 + ")|" + IPv4_ADDRESS;
    public static final String IPv6_ADDRESS = "(?:(?:(?:" + H16 + ":){6}(?:" + LS32 + "))|" + "(?:::(?:"
            + H16 + ":){5}(?:" + LS32 + "))|" + "(?:(?:"
            + H16 + "){0,1}::(?:" + H16 + ":){4}(?:" + LS32 + "))|" + "(?:(?:(?:"
            + H16 + ":){0,1}" + H16 + ")?::(?:" + H16 + ":){3}(?:" + LS32 + "))|" + "(?:(?:(?:"
            + H16 + ":){0,2}" + H16 + ")?::(?:" + H16 + ":){2}(?:" + LS32 + "))|" + "(?:(?:(?:"
            + H16 + ":){0,3}" + H16 + ")?::(?:" + H16 + ":){1}(?:" + LS32 + "))|" + "(?:(?:(?:"
            + H16 + ":){0,4}" + H16 + ")?::(?:" + LS32 + "))|" + "(?:(?:(?:"
            + H16 + ":){0,5}" + H16 + ")?::(?:" + H16 + "))|" + "(?:(?:(?:"
            + H16 + ":){0,6}" + H16 + ")?::))";
    public static final String IP_LITERAL = "\\[" + IPv6_ADDRESS + "]";
    public static final String PORT = "\\p{Digit}+";
    public static final String HOST = "(?:" + IP_LITERAL + "|" + IPv4_ADDRESS + "|" + REG_NAME + ")";
    public static final String USER_INFO =
            "(?:(?:" + UNRESERVED_CHARACTERS + ")|(?:" + PCT_ENCODED + ")|(?:" + SUB_DELIMS + "))*";
    public static final String AUTHORITY = "(?:" + USER_INFO + "@)?" + HOST + "(?::" + PORT + ")?";
    public static final String SCHEME_PATTERN = "(?!\\s*javascript)\\p{L}[\\p{L}\\p{N}+.\\-]*";
    private static final String JAVASCRIPT_SCHEME = "javascript:";
    public static final String FRAGMENT = "(?:" + PCHAR + "|/|\\?)*";
    public static final String QUERY = "(?:" + PCHAR + "|/|\\?)*";
    public static final String SEGMENT_NZ = "(?:" + PCHAR + ")+";
    public static final String SEGMENT_NZ_NC =
            "(?:" + UNRESERVED_CHARACTERS + "|" + PCT_ENCODED + "|" + SUB_DELIMS + "|@)+";
    public static final String PATH_ABEMPTY = "(?:/|(/" + SEGMENT_NZ + "/?)*)";
    public static final String PATH_ABSOLUTE = "/(?:" + SEGMENT_NZ + PATH_ABEMPTY + ")?";
    public static final String PATH_NOSCHEME = SEGMENT_NZ_NC + "(?:/|(/" + SEGMENT_NZ + ")*)";
    public static final String PATH_ROOTLESS = SEGMENT_NZ + "(?:/|(/" + SEGMENT_NZ + ")*)";
    public static final String PATH_EMPTY = "(?:^$)";
    public static final String RELATIVE_PART =
            "(?:(?://" + AUTHORITY + PATH_ABEMPTY + ")|" + "(?:" + PATH_ABSOLUTE + ")|" + "(?:" + PATH_ROOTLESS + "))";
    public static final String HIER_PART = "(?:(?://" + AUTHORITY + PATH_ABEMPTY + ")|" + "(?:"
            + PATH_ABSOLUTE + ")|" + "(?:"
            + PATH_NOSCHEME + ")|" + PATH_EMPTY
            + ")";

    public static final String RELATIVE_REF =
            "(?!\\s*javascript(?::|&colon;))" + RELATIVE_PART + "?(?:\\?" + QUERY + ")?(?:#" + FRAGMENT + ")?";
    public static final String URI = SCHEME_PATTERN + ":" + HIER_PART + "(?:\\?" + QUERY + ")?(?:#" + FRAGMENT + ")?";

    /*
     * The simplified patterns are only used when the primary RFC 3986-shaped regexes abort with a
     * StackOverflowError on pathological input (see runHrefValidation and FallbackATag). A degraded
     * fallback must never be more permissive than the primary path for scheme safety, so the same
     * javascript-scheme guard used by RELATIVE_REF is applied here as well. The guard is
     * case-insensitive as defense in depth for consumers that do not lower-case the value first.
     */
    static final Pattern ON_SITE_SIMPLIFIED = Pattern.compile("(?!\\s*(?i:javascript)(?::|&colon;))"
            + "([\\p{L}\\p{N}\\\\\\.\\#@\\$%\\+&amp;;:\\-_~,\\?=/!\\*\\(\\)]*|\\#" + "(\\w)+)");
    /*
     * The quantifiers below are possessive (`*+` / `++`) on purpose: the three quantified parts overlap
     * ([\p{L}\p{N}] is a subset of the following character class, which in turn overlaps the trailing
     * (\s)* on space characters), so with regular greedy quantifiers a non-matching input such as
     * "http://" + "a".repeat(n) + "^" triggers polynomial backtracking (O(n^2) and worse). Because each
     * quantifier iteration consumes exactly one character from a character class, making them possessive
     * does not change the accepted language - it only removes the backtracking, keeping matching linear.
     */
    static final Pattern OFF_SITE_SIMPLIFIED = Pattern.compile("(\\s)*+((ht|f)tp(s?)://|mailto:)"
            + "[\\p{L}\\p{N}]++[\\p{L}\\p{N}\\p{Zs}\\.\\#@\\$%\\+&amp;;:\\-_~,\\?=/!\\*\\(\\)]*+(\\s)*+");

    static final Attribute FALLBACK_HREF_ATTRIBUTE = new Attribute(
            "href",
            Arrays.asList(
                    new Regexp("on-site-simplified", ON_SITE_SIMPLIFIED.toString()),
                    new Regexp("off-site-simplified", OFF_SITE_SIMPLIFIED.toString())),
            Collections.emptyList(),
            AntiSamyActions.REMOVE_ATTRIBUTE_ON_INVALID,
            null);

    /**
     * Unescapes HTML character references in a single left-to-right pass, the way a browser does when
     * reading an attribute value: numeric references ({@code &#dd;} / {@code &#xhh;}, terminating
     * semicolon optional, e.g. {@code "&#106avascript:alert(1)"} decodes to {@code "javascript:alert(1)"})
     * plus named references, both the HTML 4 set known to {@link StringEscapeUtils#unescapeHtml4(String)}
     * and the HTML5-only names that resolve to ASCII characters (e.g. {@code &Tab;}, {@code &NewLine;},
     * {@code &colon;}). commons-text's {@code NumericEntityUnescaper} cannot be used for the numeric part:
     * it requires the semicolon by default, and its semiColonOptional mode mis-parses decimal references
     * followed by a hex-letter character (it reads "&#106a" as the decimal number "106a" and gives up).
     *
     * <p>Numeric and named decoding are combined into a single {@link AggregateTranslator} - and applied to
     * the URL exactly once - rather than run as two sequential passes: a two-pass approach would let a
     * character produced by the first pass be mistaken for the start of a new reference by the second pass.
     * For example {@code "&#38;Tab;"} is, per the HTML5 spec, decoded once to the literal text
     * {@code "&Tab;"} (a harmless ampersand followed by literal text); a browser does not re-scan that
     * output and would never turn it into a tab character, so this implementation must not either.
     */
    static final CharSequenceTranslator NUMERIC_ENTITY_UNESCAPER = new Html5NumericEntityUnescaper();

    static final CharSequenceTranslator UNICODE_UNESCAPER = new AggregateTranslator(
            NUMERIC_ENTITY_UNESCAPER, StringEscapeUtils.UNESCAPE_HTML4, new LookupTranslator(html5AsciiEntities()));

    private static Map<CharSequence, CharSequence> html5AsciiEntities() {
        Map<CharSequence, CharSequence> entities = new HashMap<>();
        entities.put("&Tab;", "\t");
        entities.put("&NewLine;", "\n");
        entities.put("&excl;", "!");
        entities.put("&num;", "#");
        entities.put("&dollar;", "$");
        entities.put("&percnt;", "%");
        entities.put("&apos;", "'");
        entities.put("&lpar;", "(");
        entities.put("&rpar;", ")");
        entities.put("&ast;", "*");
        entities.put("&midast;", "*");
        entities.put("&plus;", "+");
        entities.put("&comma;", ",");
        entities.put("&period;", ".");
        entities.put("&sol;", "/");
        entities.put("&colon;", ":");
        entities.put("&semi;", ";");
        entities.put("&equals;", "=");
        entities.put("&quest;", "?");
        entities.put("&commat;", "@");
        entities.put("&lsqb;", "[");
        entities.put("&lbrack;", "[");
        entities.put("&bsol;", "\\");
        entities.put("&rsqb;", "]");
        entities.put("&rbrack;", "]");
        entities.put("&Hat;", "^");
        entities.put("&lowbar;", "_");
        entities.put("&UnderBar;", "_");
        entities.put("&grave;", "`");
        entities.put("&DiacriticalGrave;", "`");
        entities.put("&lcub;", "{");
        entities.put("&lbrace;", "{");
        entities.put("&verbar;", "|");
        entities.put("&vert;", "|");
        entities.put("&VerticalLine;", "|");
        entities.put("&rcub;", "}");
        entities.put("&rbrace;", "}");
        return Collections.unmodifiableMap(entities);
    }

    /**
     * Decodes numeric character references ({@code &#dd;} / {@code &#xhh;}) the way the HTML5
     * specification requires for attribute values: the terminating semicolon is optional and a
     * decimal reference ends at the first non-decimal-digit character (so {@code &#106avascript}
     * decodes to {@code javascript}).
     */
    private static final class Html5NumericEntityUnescaper extends CharSequenceTranslator {

        @Override
        public int translate(CharSequence input, int index, Writer writer) throws IOException {
            int seqEnd = input.length();
            if (input.charAt(index) != '&' || index >= seqEnd - 2 || input.charAt(index + 1) != '#') {
                return 0;
            }
            int start = index + 2;
            boolean isHex = false;
            char firstChar = input.charAt(start);
            if (firstChar == 'x' || firstChar == 'X') {
                start++;
                isHex = true;
                if (start == seqEnd) {
                    return 0;
                }
            }
            int end = start;
            while (end < seqEnd && isEntityDigit(input.charAt(end), isHex)) {
                end++;
            }
            if (end == start) {
                return 0;
            }
            int entityValue;
            try {
                entityValue = Integer.parseInt(input.subSequence(start, end).toString(), isHex ? 16 : 10);
            } catch (NumberFormatException nfe) {
                // value too large to represent: decode to the replacement character, like browsers do
                entityValue = 0xFFFD;
            }
            if (entityValue > Character.MAX_CODE_POINT) {
                entityValue = 0xFFFD;
            }
            writer.write(new String(Character.toChars(entityValue)));
            boolean semiNext = end != seqEnd && input.charAt(end) == ';';
            return (semiNext ? end + 1 : end) - index;
        }

        private static boolean isEntityDigit(char ch, boolean isHex) {
            if (ch >= '0' && ch <= '9') {
                return true;
            }
            return isHex && (ch >= 'a' && ch <= 'f' || ch >= 'A' && ch <= 'F');
        }
    }

    // Default href configuration copied from the config.xml supplied with AntiSamy
    static final Attribute DEFAULT_HREF_ATTRIBUTE = new Attribute(
            "href",
            Arrays.asList(new Regexp("relative-ref", RELATIVE_REF), new Regexp("uri", URI)),
            null,
            AntiSamyActions.REMOVE_ATTRIBUTE_ON_INVALID,
            null);

    static final String DEFAULT_POLICY_PATH = "sling/xss/config.xml";
    static final String EMBEDDED_POLICY_PATH = "SLING-INF/content/config.xml";
    private Attribute hrefAttribute;
    private String policyPath;
    private ServiceRegistration<ResourceChangeListener> serviceRegistration;

    // available contexts
    private final XSSFilterRule htmlHtmlContext = new HtmlToHtmlContentContext();
    private final XSSFilterRule plainHtmlContext = new PlainTextToHtmlContentContext();

    private volatile AntiSamyPolicy activePolicy;

    @Reference
    private ResourceResolverFactory resourceResolverFactory;

    @Reference
    private ServiceUserMapped serviceUserMapped;

    @Reference(
            policy = ReferencePolicy.DYNAMIC,
            cardinality = ReferenceCardinality.OPTIONAL,
            policyOption = ReferencePolicyOption.GREEDY)
    private volatile XSSMetricsService metricsService;

    @Reference
    private XSSStatusService statusService;

    @Override
    public boolean check(final ProtectionContext context, final String src) {
        final XSSFilterRule ctx = this.getFilterRule(context);
        return ctx.check(getPolicyHandler(), src);
    }

    @Override
    public String filter(final String src) {
        return this.filter(XSSFilter.DEFAULT_CONTEXT, src);
    }

    @Override
    public String filter(final ProtectionContext context, final String src) {
        final XSSFilterRule ctx = this.getFilterRule(context);
        return ctx.filter(getPolicyHandler(), src);
    }

    private @Nullable PolicyHandler getPolicyHandler() {
        return Optional.ofNullable(getActivePolicy())
                .map(AntiSamyPolicy::getPolicyHandler)
                .orElse(null);
    }

    @Override
    public boolean isValidHref(String url) {
        if (StringUtils.isEmpty(url)) {
            return true;
        }
        try {
            String decodedURL = URLDecoder.decode(url, StandardCharsets.UTF_8.name());
            if (hasJavaScriptSchemeAfterBrowserParsing(decodedURL)) {
                reportInvalidUrl(url);
                return false;
            }
            String numericUnescapedUrl = NUMERIC_ENTITY_UNESCAPER.translate(decodedURL);
            // Decode numeric and named character references in a single pass over whichever base string is
            // chosen below: chaining two separate translate() calls would let a character produced by the
            // first pass (e.g. the '&' decoded from "&#38;") be mistaken by the second pass for the start of
            // a new reference, which a browser never does (see UNICODE_UNESCAPER's javadoc).
            String baseUrl = numericUnescapedUrl.equals(decodedURL) ? url : decodedURL;
            String urlToValidate = UNICODE_UNESCAPER.translate(baseUrl);
            return runHrefValidation(urlToValidate);
        } catch (Exception e) {
            logger.warn("Unable to validate url.", e);
            logger.debug("URL input: {}", url);
        }
        return false;
    }

    public AntiSamyPolicy getActivePolicy() {
        return activePolicy;
    }

    public void writeActivePolicyConfig(OutputStream outputStream) {
        withPolicyResource(policyResource -> {
            activePolicy.writeConfig(policyResource, outputStream);
            return null;
        });
    }

    private static boolean hasJavaScriptSchemeAfterBrowserParsing(@NotNull String url) {
        String canonicalUrl = canonicalizeForBrowserSchemeParsing(url);
        return StringUtils.startsWithIgnoreCase(canonicalUrl, JAVASCRIPT_SCHEME);
    }

    private static String canonicalizeForBrowserSchemeParsing(@NotNull String url) {
        String htmlAttributeValue = decodeHtmlCharacterReferencesOnce(url);
        String strippedUrl = stripLeadingAndTrailingC0ControlOrSpace(htmlAttributeValue);
        return removeAsciiTabOrNewline(strippedUrl);
    }

    private static String decodeHtmlCharacterReferencesOnce(@NotNull String value) {
        StringBuilder result = new StringBuilder(value.length());
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (character == '&') {
                int nextIndex = decodeHtmlCharacterReferenceAt(value, index, result);
                if (nextIndex > index) {
                    index = nextIndex - 1;
                    continue;
                }
            }
            result.append(character);
        }
        return result.toString();
    }

    private static int decodeHtmlCharacterReferenceAt(@NotNull String value, int start, @NotNull StringBuilder result) {
        if (value.startsWith("&Tab;", start)) {
            result.append('\t');
            return start + 5;
        }
        if (value.startsWith("&NewLine;", start)) {
            result.append('\n');
            return start + 9;
        }
        if (value.startsWith("&colon;", start)) {
            result.append(':');
            return start + 7;
        }
        if (start + 2 < value.length() && value.charAt(start + 1) == '#') {
            return decodeNumericCharacterReferenceAt(value, start, result);
        }
        return -1;
    }

    private static int decodeNumericCharacterReferenceAt(
            @NotNull String value, int start, @NotNull StringBuilder result) {
        int index = start + 2;
        int radix = 10;
        if (index < value.length() && (value.charAt(index) == 'x' || value.charAt(index) == 'X')) {
            radix = 16;
            index++;
        }

        int digitsStart = index;
        while (index < value.length() && Character.digit(value.charAt(index), radix) != -1) {
            index++;
        }
        if (index == digitsStart) {
            return -1;
        }

        int codePoint;
        try {
            codePoint = Integer.parseUnsignedInt(value.substring(digitsStart, index), radix);
        } catch (NumberFormatException e) {
            return -1;
        }
        if (!Character.isValidCodePoint(codePoint)) {
            return -1;
        }

        if (index < value.length() && value.charAt(index) == ';') {
            index++;
        }
        result.appendCodePoint(codePoint);
        return index;
    }

    private static String stripLeadingAndTrailingC0ControlOrSpace(@NotNull String value) {
        int start = 0;
        int end = value.length();
        while (start < end && isC0ControlOrSpace(value.charAt(start))) {
            start++;
        }
        while (end > start && isC0ControlOrSpace(value.charAt(end - 1))) {
            end--;
        }
        return value.substring(start, end);
    }

    private static String removeAsciiTabOrNewline(@NotNull String value) {
        StringBuilder result = new StringBuilder(value.length());
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (!isAsciiTabOrNewline(character)) {
                result.append(character);
            }
        }
        return result.toString();
    }

    private static boolean isC0ControlOrSpace(char character) {
        return character <= ' ';
    }

    private static boolean isAsciiTabOrNewline(char character) {
        return character == '\t' || character == '\n' || character == '\r';
    }

    private boolean runHrefValidation(@NotNull String url) {
        // Same logic as in org.owasp.validator.html.scan.MagicSAXFilter.startElement()
        String urlLowerCase = url.toLowerCase();
        boolean isValid = hrefAttribute.containsAllowedValue(urlLowerCase);
        if (!isValid) {
            try {
                isValid = hrefAttribute.matchesAllowedExpression(urlLowerCase);
            } catch (StackOverflowError e) {
                logger.debug(
                        "Detected a StackOverflowError when validating url {} with configured regexes. Trying fallback.",
                        url);
                try {
                    isValid = FALLBACK_HREF_ATTRIBUTE.containsAllowedValue(urlLowerCase);
                    if (!isValid) {
                        isValid = FALLBACK_HREF_ATTRIBUTE.matchesAllowedExpression(urlLowerCase);
                    }
                } catch (StackOverflowError inner) {
                    logger.debug("Detected a StackOverflowError when validating url {} with fallback regexes", url);
                }
            }
        }
        if (!isValid) {
            reportInvalidUrl(url);
        }
        return isValid;
    }

    private void reportInvalidUrl(@NotNull String url) {
        statusService.reportInvalidUrl(url);
        Optional.ofNullable(metricsService).ifPresent(service -> service.invalidHref());
    }

    @Activate
    @Modified
    protected void activate(ComponentContext componentContext, Configuration configuration) {
        // load default handler
        policyPath = configuration.policyPath();
        updateActivePolicy();
        if (serviceRegistration != null) {
            serviceRegistration.unregister();
        }
        Dictionary<String, Object> rclProperties = new Hashtable<>();
        rclProperties.put(ResourceChangeListener.CHANGES, new String[] {"ADDED", "CHANGED", "REMOVED"});
        rclProperties.put(ResourceChangeListener.PATHS, policyPath);
        serviceRegistration = componentContext
                .getBundleContext()
                .registerService(ResourceChangeListener.class, new PolicyChangeListener(), rclProperties);
        logger.info("Registered a resource change listener for file {}.", policyPath);
    }

    @Deactivate
    protected void deactivate() {
        if (serviceRegistration != null) {
            serviceRegistration.unregister();
        }
    }

    synchronized void updateActivePolicy() {
        final AntiSamyPolicy originalActivePolicy = this.activePolicy;
        this.activePolicy = withPolicyResource(AntiSamyPolicy::create);
        // the originalActivePolicy can only be null during the first activation
        if (activePolicy == null && originalActivePolicy == null) {
            // the content-based policy file is not (yet) available, fall back to the embedded policy
            this.activePolicy = AntiSamyPolicy.createEmbedded();
            if (activePolicy == null) {
                throw new IllegalStateException("Cannot load a policy handler.");
            }
        }
        updatePolicyHandler(activePolicy.getPolicyHandler());
    }

    private <T> T withPolicyResource(Function<Resource, T> mapper) {
        try (final ResourceResolver xssResourceResolver = resourceResolverFactory.getServiceResourceResolver(null)) {
            Resource policyResource = xssResourceResolver.getResource(policyPath);
            if (policyResource != null) {
                return mapper.apply(policyResource);
            }
        } catch (final LoginException e) {
            logger.error("Unable to load the default policy file.", e);
        }
        return null;
    }

    /**
     * Get the filter rule context.
     */
    private XSSFilterRule getFilterRule(final ProtectionContext context) {
        if (context == null) {
            throw new NullPointerException("context");
        }
        if (context == ProtectionContext.HTML_HTML_CONTENT) {
            return this.htmlHtmlContext;
        }
        return this.plainHtmlContext;
    }

    private void updatePolicyHandler(PolicyHandler policyHandler) {
        Tag linkTag = policyHandler.getPolicy().getTagRules().get("a");
        hrefAttribute = (linkTag != null) ? linkTag.getAttributeByName("href") : null;
        if (hrefAttribute == null) {
            // Fallback to default configuration
            hrefAttribute = DEFAULT_HREF_ATTRIBUTE;
        }
    }

    private class PolicyChangeListener implements ResourceChangeListener, ExternalResourceChangeListener {
        @Override
        public void onChange(@NotNull List<ResourceChange> resourceChanges) {
            for (ResourceChange change : resourceChanges) {
                if (change.getPath().endsWith(policyPath)) {
                    logger.info(
                            "Detected policy file change ({}) at {}. Updating policy handler.",
                            change.getType().name(),
                            change.getPath());
                    updateActivePolicy();
                }
            }
        }
    }

    public static class AntiSamyPolicy {

        private final String policyPath;

        private final PolicyHandler policyHandler;

        public static AntiSamyPolicy create(Resource policyResource) {
            String policyPath = policyResource.getPath();
            return createAntiSamyPolicy(policyPath, () -> streamResource(policyResource));
        }

        public static AntiSamyPolicy createEmbedded() {
            return createAntiSamyPolicy(null, AntiSamyPolicy::streamEmbedded);
        }

        private static AntiSamyPolicy createAntiSamyPolicy(
                @Nullable String policyPath, @NotNull Supplier<InputStream> policySupplier) {
            String pathName = policyPath == null ? "embedded policy file" : policyPath;
            try (InputStream policyStream = policySupplier.get()) {
                PolicyHandler policyHandler = new PolicyHandler(policyStream);
                logger.info("Installed policy from {}.", pathName);
                return new AntiSamyPolicy(policyHandler, policyPath);
            } catch (Exception e) {
                logger.error("Unable to load policy from {}.", pathName, e);
                return null;
            }
        }

        private AntiSamyPolicy(@NotNull PolicyHandler policyHandler, @Nullable String policyPath) {
            this.policyPath = policyPath;
            this.policyHandler = policyHandler;
        }

        public boolean isEmbedded() {
            return policyPath == null;
        }

        public String getPath() {
            return isEmbedded() ? EMBEDDED_POLICY_PATH : policyPath;
        }

        public PolicyHandler getPolicyHandler() {
            return policyHandler;
        }

        public void writeConfig(Resource policyResource, OutputStream outputStream) {
            try (InputStream inputStream = isEmbedded() ? streamEmbedded() : streamResource(policyResource)) {
                if (inputStream != null) {
                    IOUtils.copy(inputStream, outputStream);
                }
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }

        private static @Nullable InputStream streamResource(Resource policyResource) {
            return policyResource.adaptTo(InputStream.class);
        }

        private static @Nullable InputStream streamEmbedded() {
            return XSSFilterImpl.class.getClassLoader().getResourceAsStream(EMBEDDED_POLICY_PATH);
        }
    }
}
