package com.example.training;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.io.StringWriter;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Test suite for VulnerableServlet - specifically testing the XSS vulnerability remediation
 * in the renderSearchPage method.
 *
 * These tests verify that:
 * 1. User input is properly HTML-encoded to prevent XSS attacks
 * 2. Normal functionality is preserved
 * 3. Various XSS attack vectors are properly neutralized
 * 4. Edge cases (null, empty, special characters) are handled correctly
 */
@DisplayName("VulnerableServlet - XSS Remediation Tests")
public class VulnerableServletTest {

    private VulnerableServlet servlet;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    private StringWriter responseWriter;
    private PrintWriter printWriter;

    @BeforeEach
    public void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        servlet = new VulnerableServlet();

        // Set up response writer to capture output
        responseWriter = new StringWriter();
        printWriter = new PrintWriter(responseWriter);
        when(response.getWriter()).thenReturn(printWriter);
    }

    @Test
    @DisplayName("Should encode HTML script tag in search query")
    public void testScriptTagIsEncoded() throws Exception {
        // Test the most common XSS attack vector: <script> tags
        String maliciousInput = "<script>alert('XSS')</script>";
        when(request.getParameter("q")).thenReturn(maliciousInput);

        servlet.renderSearchPage(request, response);
        printWriter.flush();

        String output = responseWriter.toString();

        // Verify that script tags are encoded
        assertFalse(output.contains("<script>"), "Output should not contain unencoded <script> tag");
        assertFalse(output.contains("</script>"), "Output should not contain unencoded </script> tag");
        assertTrue(output.contains("&lt;script&gt;"), "Output should contain encoded script tag");
        assertTrue(output.contains("&lt;/script&gt;"), "Output should contain encoded closing script tag");
    }

    @Test
    @DisplayName("Should encode HTML img tag with onerror XSS payload")
    public void testImgTagWithOnErrorIsEncoded() throws Exception {
        // Test image-based XSS attack
        String maliciousInput = "<img src=x onerror='alert(1)'>";
        when(request.getParameter("q")).thenReturn(maliciousInput);

        servlet.renderSearchPage(request, response);
        printWriter.flush();

        String output = responseWriter.toString();

        // Verify that < > and ' are all encoded
        assertFalse(output.contains("<img"), "Output should not contain unencoded <img tag");
        assertTrue(output.contains("&lt;img"), "Output should contain encoded img tag");
        assertTrue(output.contains("&#x27;"), "Output should contain encoded single quotes");
    }

    @Test
    @DisplayName("Should encode SVG-based XSS payload")
    public void testSvgXssIsEncoded() throws Exception {
        // Test SVG-based XSS attack
        String maliciousInput = "<svg/onload=alert('XSS')>";
        when(request.getParameter("q")).thenReturn(maliciousInput);

        servlet.renderSearchPage(request, response);
        printWriter.flush();

        String output = responseWriter.toString();

        // Verify SVG tags are encoded
        assertFalse(output.contains("<svg"), "Output should not contain unencoded <svg tag");
        assertTrue(output.contains("&lt;svg"), "Output should contain encoded svg tag");
        assertTrue(output.contains("&gt;"), "Output should contain encoded > character");
    }

    @Test
    @DisplayName("Should encode JavaScript event handler attributes")
    public void testEventHandlerIsEncoded() throws Exception {
        // Test event handler XSS
        String maliciousInput = "\" onclick=\"alert('XSS')\"";
        when(request.getParameter("q")).thenReturn(maliciousInput);

        servlet.renderSearchPage(request, response);
        printWriter.flush();

        String output = responseWriter.toString();

        // Verify quotes are encoded
        assertFalse(output.contains("onclick="), "Output should not allow onclick attribute injection");
        assertTrue(output.contains("&quot;"), "Output should contain encoded double quotes");
    }

    @Test
    @DisplayName("Should encode HTML anchor tag with javascript: protocol")
    public void testJavascriptProtocolIsEncoded() throws Exception {
        // Test javascript: protocol XSS
        String maliciousInput = "<a href='javascript:alert(1)'>Click</a>";
        when(request.getParameter("q")).thenReturn(maliciousInput);

        servlet.renderSearchPage(request, response);
        printWriter.flush();

        String output = responseWriter.toString();

        // Verify tags are encoded
        assertFalse(output.contains("<a href"), "Output should not contain unencoded anchor tag");
        assertTrue(output.contains("&lt;a href"), "Output should contain encoded anchor tag");
    }

    @Test
    @DisplayName("Should encode all dangerous HTML special characters")
    public void testAllSpecialCharactersAreEncoded() throws Exception {
        // Test that all dangerous characters are encoded
        String maliciousInput = "<>&\"'";
        when(request.getParameter("q")).thenReturn(maliciousInput);

        servlet.renderSearchPage(request, response);
        printWriter.flush();

        String output = responseWriter.toString();

        // Verify all special characters are encoded
        String searchResult = output.substring(output.indexOf("You searched for: ") + 18);
        assertTrue(searchResult.contains("&lt;"), "Should encode <");
        assertTrue(searchResult.contains("&gt;"), "Should encode >");
        assertTrue(searchResult.contains("&amp;"), "Should encode &");
        assertTrue(searchResult.contains("&quot;"), "Should encode \"");
        assertTrue(searchResult.contains("&#x27;"), "Should encode '");
    }

    @Test
    @DisplayName("Should handle normal alphanumeric search query without corruption")
    public void testNormalQueryIsNotCorrupted() throws Exception {
        // Verify that legitimate queries still work correctly
        String normalInput = "laptop computers";
        when(request.getParameter("q")).thenReturn(normalInput);

        servlet.renderSearchPage(request, response);
        printWriter.flush();

        String output = responseWriter.toString();

        // Verify normal text passes through unchanged
        assertTrue(output.contains("You searched for: laptop computers"),
                   "Normal text should appear unchanged in output");
        assertTrue(output.contains("<html><body>"), "HTML structure should be intact");
        assertTrue(output.contains("</body></html>"), "HTML closing tags should be intact");
    }

    @Test
    @DisplayName("Should handle search query with spaces and punctuation")
    public void testQueryWithSpacesAndPunctuation() throws Exception {
        // Test that safe punctuation is preserved
        String normalInput = "How much does it cost?";
        when(request.getParameter("q")).thenReturn(normalInput);

        servlet.renderSearchPage(request, response);
        printWriter.flush();

        String output = responseWriter.toString();

        // Verify spaces and safe punctuation are preserved
        assertTrue(output.contains("How much does it cost?"),
                   "Spaces and safe punctuation should be preserved");
    }

    @Test
    @DisplayName("Should handle null query parameter safely")
    public void testNullQueryParameter() throws Exception {
        // Test null input handling
        when(request.getParameter("q")).thenReturn(null);

        servlet.renderSearchPage(request, response);
        printWriter.flush();

        String output = responseWriter.toString();

        // Verify null is handled gracefully (should not throw exception)
        assertTrue(output.contains("You searched for:"), "Should handle null input");
        assertFalse(output.contains("null"), "Should not display 'null' string");
    }

    @Test
    @DisplayName("Should handle empty query parameter")
    public void testEmptyQueryParameter() throws Exception {
        // Test empty string input
        when(request.getParameter("q")).thenReturn("");

        servlet.renderSearchPage(request, response);
        printWriter.flush();

        String output = responseWriter.toString();

        // Verify empty string is handled correctly
        assertTrue(output.contains("You searched for: </h2>"),
                   "Should handle empty query correctly");
    }

    @Test
    @DisplayName("Should encode polyglot XSS payload")
    public void testPolyglotXssPayload() throws Exception {
        // Test complex polyglot payload that works in multiple contexts
        String maliciousInput = "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>";
        when(request.getParameter("q")).thenReturn(maliciousInput);

        servlet.renderSearchPage(request, response);
        printWriter.flush();

        String output = responseWriter.toString();

        // Verify dangerous characters are all encoded
        assertFalse(output.contains("<sVg"), "Should encode SVG tag variants");
        assertFalse(output.contains("</stYle"), "Should encode style closing tag");
        assertFalse(output.contains("</scRipt"), "Should encode script closing tag");
        assertTrue(output.contains("&lt;"), "Should contain encoded < characters");
        assertTrue(output.contains("&gt;"), "Should contain encoded > characters");
    }

    @Test
    @DisplayName("Should encode HTML entities double-encoding attack")
    public void testDoubleEncodingAttack() throws Exception {
        // Test that already-encoded entities don't create vulnerability
        String maliciousInput = "&lt;script&gt;alert('XSS')&lt;/script&gt;";
        when(request.getParameter("q")).thenReturn(maliciousInput);

        servlet.renderSearchPage(request, response);
        printWriter.flush();

        String output = responseWriter.toString();

        // Verify that & is encoded to prevent double-decoding attacks
        assertTrue(output.contains("&amp;lt;"),
                   "Ampersands should be encoded to prevent double-decoding");
    }

    @Test
    @DisplayName("Should set correct content type for HTML response")
    public void testContentTypeIsSet() throws Exception {
        when(request.getParameter("q")).thenReturn("test");

        servlet.renderSearchPage(request, response);

        // Verify content type is set correctly
        verify(response).setContentType("text/html");
    }

    @Test
    @DisplayName("Should set security headers for XSS protection")
    public void testSecurityHeadersAreSet() throws Exception {
        when(request.getParameter("q")).thenReturn("test");

        servlet.renderSearchPage(request, response);

        // Verify security headers are set
        verify(response).setHeader("Strict-Transport-Security",
                                   "max-age=31536000; includeSubDomains");
        verify(response).setHeader("X-Content-Type-Options", "nosniff");
    }

    @Test
    @DisplayName("Should encode mixed content with XSS and normal text")
    public void testMixedContentEncoding() throws Exception {
        // Test realistic attack where XSS is mixed with normal text
        String maliciousInput = "laptop <script>alert('XSS')</script> computers";
        when(request.getParameter("q")).thenReturn(maliciousInput);

        servlet.renderSearchPage(request, response);
        printWriter.flush();

        String output = responseWriter.toString();

        // Verify normal text is preserved while XSS is encoded
        assertTrue(output.contains("laptop"), "Normal text should be preserved");
        assertTrue(output.contains("computers"), "Normal text should be preserved");
        assertFalse(output.contains("<script>"), "Script tags should be encoded");
        assertTrue(output.contains("&lt;script&gt;"), "Script tags should be HTML-encoded");
    }

    @Test
    @DisplayName("Should encode data: protocol XSS attempt")
    public void testDataProtocolXss() throws Exception {
        // Test data: protocol XSS
        String maliciousInput = "<a href='data:text/html,<script>alert(1)</script>'>Click</a>";
        when(request.getParameter("q")).thenReturn(maliciousInput);

        servlet.renderSearchPage(request, response);
        printWriter.flush();

        String output = responseWriter.toString();

        // Verify complete encoding
        assertFalse(output.contains("<a href="), "Anchor tag should be encoded");
        assertFalse(output.contains("<script>"), "Script tag should be encoded");
        assertTrue(output.contains("&lt;"), "< should be encoded");
        assertTrue(output.contains("&gt;"), "> should be encoded");
    }

    @Test
    @DisplayName("Should handle unicode characters in query")
    public void testUnicodeCharacters() throws Exception {
        // Test that unicode characters are preserved
        String unicodeInput = "café résumé 日本語";
        when(request.getParameter("q")).thenReturn(unicodeInput);

        servlet.renderSearchPage(request, response);
        printWriter.flush();

        String output = responseWriter.toString();

        // Verify unicode is preserved (not over-encoded)
        assertTrue(output.contains("café"), "Unicode characters should be preserved");
        assertTrue(output.contains("résumé"), "Unicode characters should be preserved");
        assertTrue(output.contains("日本語"), "Unicode characters should be preserved");
    }

    @Test
    @DisplayName("Should encode HTML comment-based XSS")
    public void testHtmlCommentXss() throws Exception {
        // Test HTML comment XSS bypass attempt
        String maliciousInput = "<!--<script>alert('XSS')</script>-->";
        when(request.getParameter("q")).thenReturn(maliciousInput);

        servlet.renderSearchPage(request, response);
        printWriter.flush();

        String output = responseWriter.toString();

        // Verify HTML comments are encoded
        assertFalse(output.contains("<!--"), "HTML comment start should be encoded");
        assertFalse(output.contains("-->"), "HTML comment end should be encoded");
        assertTrue(output.contains("&lt;!--"), "Comment should be HTML-encoded");
    }
}
