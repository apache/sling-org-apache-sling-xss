/*******************************************************************************
 * Licensed to the Apache Software Foundation (ASF) under one or
 * more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information regarding
 * copyright ownership. The ASF licenses this file to you under the
 * Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0 Unless required by
 * applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 ******************************************************************************/
package org.apache.sling.xss.impl;

import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

import javax.annotation.Nonnull;

import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.commons.lang3.StringUtils;
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
import org.osgi.framework.Constants;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.owasp.validator.html.model.Attribute;
import org.owasp.validator.html.model.Tag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class implements the <code>XSSFilter</code> using the Antisamy XSS protection library found at
 * <a href="http://code.google.com/p/owaspantisamy/">http://code.google.com/p/owaspantisamy/</a>.
 */
@Component(
        service = {ResourceChangeListener.class, XSSFilter.class},
        property = {
                Constants.SERVICE_VENDOR + "=The Apache Software Foundation",
                ResourceChangeListener.CHANGES + "=ADDED",
                ResourceChangeListener.CHANGES + "=CHANGED",
                ResourceChangeListener.CHANGES + "=REMOVED",
                ResourceChangeListener.PATHS + "=" + XSSFilterImpl.DEFAULT_POLICY_PATH
        }
)
public class XSSFilterImpl implements XSSFilter, ResourceChangeListener, ExternalResourceChangeListener {

    private final Logger logger = LoggerFactory.getLogger(XSSFilterImpl.class);

    public static final String GRAPHEME = "(?>\\P{M}\\p{M}*)";
    public static final String ALPHA = "(?:\\p{L}\\p{M}*)";
    public static final String HEX_DIGIT = "\\p{XDigit}";
    public static final String PCT_ENCODED = "%" + HEX_DIGIT + HEX_DIGIT;
    public static final String UNRESERVED_CHARACTERS = ALPHA + "|[\\p{N}-._~]";
    public static final String SUB_DELIMS = "[!$&'()*+,;=]";
    public static final String REG_NAME = "(?:(?:" + UNRESERVED_CHARACTERS + ")*|(?:" + PCT_ENCODED + ")*|" + "(?:" + SUB_DELIMS + ")*)";
    public static final String PCHAR = UNRESERVED_CHARACTERS + "|" + PCT_ENCODED + "|" + SUB_DELIMS + "|:|@";
    public static final String DEC_OCTET = "(?:\\p{N}|[\\x31-\\x39]\\p{N}|1\\p{N}{2}|2[\\x30-\\x34]\\p{N}|25[\\x30-\\x35])";
    public static final String H16 = HEX_DIGIT + "{1,4}";
    public static final String IPv4_ADDRESS = DEC_OCTET + "\\." + DEC_OCTET + "\\." + DEC_OCTET + "\\." + DEC_OCTET;
    public static final String LS32 = "(?:" + H16 + ":" + H16 + ")|" + IPv4_ADDRESS;
    public static final String IPv6_ADDRESS = "(?:(?:(?:" + H16 + ":){6}(?:" + LS32 + "))|" +
            "(?:::(?:" + H16 + ":){5}(?:" + LS32 + "))|" +
            "(?:(?:" + H16 + "){0,1}::(?:" + H16 + ":){4}(?:" + LS32 + "))|" +
            "(?:(?:(?:" + H16 + ":){0,1}" + H16 + ")?::(?:" + H16 + ":){3}(?:" + LS32 + "))|" +
            "(?:(?:(?:" + H16 + ":){0,2}" + H16 + ")?::(?:" + H16 + ":){2}(?:" + LS32 + "))|" +
            "(?:(?:(?:" + H16 + ":){0,3}" + H16 + ")?::(?:" + H16 + ":){1}(?:" + LS32 + "))|" +
            "(?:(?:(?:" + H16 + ":){0,4}" + H16 + ")?::(?:" + LS32 + "))|" +
            "(?:(?:(?:" + H16 + ":){0,5}" + H16 + ")?::(?:" + H16 + "))|" +
            "(?:(?:(?:" + H16 + ":){0,6}" + H16 + ")?::))";
    public static final String IP_LITERAL = "\\[" + IPv6_ADDRESS + "]";
    public static final String PORT = "\\p{Digit}+";
    public static final String HOST = "(?:" + IP_LITERAL + "|" + IPv4_ADDRESS + "|" + REG_NAME + ")";
    public static final String USER_INFO = "(?:(?:" + UNRESERVED_CHARACTERS + ")|(?:" + PCT_ENCODED + ")|(?:" + SUB_DELIMS + "))*";
    public static final String AUTHORITY = "(?:" + USER_INFO + "@)?" + HOST + "(?::" + PORT + ")?";
    public static final String SCHEME_PATTERN = "(?!\\s*javascript)\\p{L}[\\p{L}\\p{N}+.\\-]*";
    public static final String FRAGMENT = "(?:" + PCHAR + "|/|\\?)*";
    public static final String QUERY = "(?:" + PCHAR + "|/|\\?)*";
    public static final String SEGMENT_NZ = "(?:" + PCHAR + ")+";
    public static final String SEGMENT_NZ_NC = "(?:" + UNRESERVED_CHARACTERS + "|" + PCT_ENCODED + "|" + SUB_DELIMS + "|@)+";
    public static final String PATH_ABEMPTY = "(?:/|(/" + SEGMENT_NZ + ")*)";
    public static final String PATH_ABSOLUTE = "/(?:" + SEGMENT_NZ + PATH_ABEMPTY + ")?";
    public static final String PATH_NOSCHEME = SEGMENT_NZ_NC + "(?:/|(/" + SEGMENT_NZ + ")*)";
    public static final String PATH_ROOTLESS = SEGMENT_NZ + "(?:/|(/" + SEGMENT_NZ + ")*)";
    public static final String PATH_EMPTY = "(?:^$)";
    public static final String RELATIVE_PART = "(?:(?://" + AUTHORITY + PATH_ABEMPTY +  ")|" +
            "(?:" + PATH_ABSOLUTE + ")|" +
            "(?:" + PATH_ROOTLESS + ")|" +
            PATH_EMPTY + ")";
    public static final String HIER_PART = "(?:(?://" + AUTHORITY + PATH_ABEMPTY + ")|" +
            "(?:" + PATH_ABSOLUTE + ")|" +
            "(?:" + PATH_NOSCHEME + ")|" +
            PATH_EMPTY + ")";

    public static final String RELATIVE_REF = "(?!\\s*javascript(?::|&colon;))" + RELATIVE_PART + "(?:\\?" + QUERY + ")?(?:#" + FRAGMENT + ")?";
    public static final String URI = SCHEME_PATTERN + ":" + HIER_PART + "(?:\\?" + QUERY + ")?(?:#" + FRAGMENT + ")?";


    // Default href configuration copied from the config.xml supplied with AntiSamy
    static final Attribute DEFAULT_HREF_ATTRIBUTE = new Attribute(
            "href",
            Arrays.asList(
                    Pattern.compile(RELATIVE_REF),
                    Pattern.compile(URI)
            ),
            Collections.<String>emptyList(),
            "removeAttribute", ""
    );

    static final String DEFAULT_POLICY_PATH = "sling/xss/config.xml";
    private static final String EMBEDDED_POLICY_PATH = "SLING-INF/content/config.xml";
    private static final int DEFAULT_POLICY_CACHE_SIZE = 128;
    private PolicyHandler defaultHandler;
    private Attribute hrefAttribute;

    // available contexts
    private final XSSFilterRule htmlHtmlContext = new HtmlToHtmlContentContext();
    private final XSSFilterRule plainHtmlContext = new PlainTextToHtmlContentContext();

    // policies cache
    private final Map<String, PolicyHandler> policies = new ConcurrentHashMap<>();

    @Reference
    private ResourceResolverFactory resourceResolverFactory;

    @Reference
    private ServiceUserMapped serviceUserMapped;

    @Override
    public void onChange(@Nonnull List<ResourceChange> resourceChanges) {
        for (ResourceChange change : resourceChanges) {
            if (change.getPath().endsWith(DEFAULT_POLICY_PATH)) {
                logger.info("Detected policy file change ({}) at {}. Updating default handler.", change.getType().name(), change.getPath());
                updateDefaultHandler();
            }
        }
    }

    @Override
    public boolean check(final ProtectionContext context, final String src) {
        return this.check(context, src, null);
    }

    @Override
    public String filter(final String src) {
        return this.filter(XSSFilter.DEFAULT_CONTEXT, src);
    }

    @Override
    public String filter(final ProtectionContext context, final String src) {
        return this.filter(context, src, null);
    }

    @Override
    public boolean isValidHref(String url) {
        if (StringUtils.isEmpty(url)) {
            return true;
        }
        try {
            String decodedURL = URLDecoder.decode(url, StandardCharsets.UTF_8.name());
            /*
                StringEscapeUtils is deprecated starting with version 3.6 of commons-lang3, however the indicated replacement comes from
                commons-text, which is not an OSGi bundle
             */
            String xmlDecodedURL = StringEscapeUtils.unescapeXml(decodedURL);
            if (xmlDecodedURL.equals(url) || xmlDecodedURL.equals(decodedURL)) {
                return runHrefValidation(url);
            }
            return runHrefValidation(xmlDecodedURL);
        } catch (UnsupportedEncodingException e) {
            logger.warn("Unable to decode url.", e);
            logger.debug("URL input: {}", url);
        }
        return false;
    }

    private boolean runHrefValidation(@Nonnull String url) {
        // Same logic as in org.owasp.validator.html.scan.MagicSAXFilter.startElement()
        boolean isValid = hrefAttribute.containsAllowedValue(url.toLowerCase());
        if (!isValid) {
            isValid = hrefAttribute.matchesAllowedExpression(url.toLowerCase());
        }
        return isValid;
    }

    @Activate
    protected void activate() {
        // load default handler
        updateDefaultHandler();
    }

    /*
        The following methods are not part of the API. Client-code dependency to these methods is risky as they can be removed at any
        point in time from the implementation.
     */

    public boolean check(final ProtectionContext context, final String src, final String policy) {
        final XSSFilterRule ctx = this.getFilterRule(context);
        PolicyHandler handler = null;
        if (ctx.supportsPolicy()) {
            if (policy == null || (handler = policies.get(policy)) == null) {
                handler = defaultHandler;
            }
        }
        return ctx.check(handler, src);
    }

    public String filter(final ProtectionContext context, final String src, final String policy) {
        if (src == null) {
            return "";
        }
        final XSSFilterRule ctx = this.getFilterRule(context);
        PolicyHandler handler = null;
        if (ctx.supportsPolicy()) {
            if (policy == null || (handler = policies.get(policy)) == null) {
                handler = defaultHandler;
            }
        }
        return ctx.filter(handler, src);
    }

    public void setDefaultPolicy(InputStream policyStream) throws Exception {
        setDefaultHandler(new PolicyHandler(policyStream));
    }

    public void resetDefaultPolicy() {
        updateDefaultHandler();
    }

    public void loadPolicy(String policyName, InputStream policyStream) throws Exception {
        if (policies.size() < DEFAULT_POLICY_CACHE_SIZE) {
            PolicyHandler policyHandler = new PolicyHandler(policyStream);
            policies.put(policyName, policyHandler);
        }
    }

    public void unloadPolicy(String policyName) {
        policies.remove(policyName);
    }

    public boolean hasPolicy(String policyName) {
        return policies.containsKey(policyName);
    }

    private synchronized void updateDefaultHandler() {
        this.defaultHandler = null;
        try (final ResourceResolver xssResourceResolver = resourceResolverFactory.getServiceResourceResolver(null)) {
            Resource policyResource = xssResourceResolver.getResource(DEFAULT_POLICY_PATH);
            if (policyResource != null) {
                try (InputStream policyStream = policyResource.adaptTo(InputStream.class)) {
                    setDefaultHandler(new PolicyHandler(policyStream));
                    logger.info("Installed default policy from {}.", policyResource.getPath());
                } catch (Exception e) {
                    Throwable[] suppressed = e.getSuppressed();
                    if (suppressed.length > 0) {
                        for (Throwable t : suppressed) {
                            logger.error("Unable to load policy from " + policyResource.getPath(), t);
                        }
                    }
                    logger.error("Unable to load policy from " + policyResource.getPath(), e);
                }
            }
        } catch (final LoginException e) {
            logger.error("Unable to load the default policy file.", e);
        }
        if (defaultHandler == null) {
            // the content was not installed but the service is active; let's use the embedded file for the default handler
            logger.info("Could not find a policy file at the default location {}. Attempting to use the default resource embedded in" +
                    " the bundle.", DEFAULT_POLICY_PATH);
            try (InputStream policyStream = this.getClass().getClassLoader().getResourceAsStream(EMBEDDED_POLICY_PATH)) {
                setDefaultHandler(new PolicyHandler(policyStream));
                logger.info("Installed default policy from the embedded {} file from the bundle.", EMBEDDED_POLICY_PATH);
            } catch (Exception e) {
                Throwable[] suppressed = e.getSuppressed();
                if (suppressed.length > 0) {
                    for (Throwable t : suppressed) {
                        logger.error("Unable to load policy from embedded policy file.", t);
                    }
                }
                logger.error("Unable to load policy from embedded policy file.", e);
            }
        }
        if (defaultHandler == null) {
            throw new IllegalStateException("Cannot load a default policy handler.");
        }
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

    private void setDefaultHandler(PolicyHandler defaultHandler) {
        Tag linkTag = defaultHandler.getPolicy().getTagByLowercaseName("a");
        Attribute hrefAttribute = (linkTag != null) ? linkTag.getAttributeByName("href") : null;
        if (hrefAttribute == null) {
            // Fallback to default configuration
            hrefAttribute = DEFAULT_HREF_ATTRIBUTE;
        }

        this.defaultHandler = defaultHandler;
        this.hrefAttribute = hrefAttribute;
    }
}
