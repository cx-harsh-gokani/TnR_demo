package com.example.training;

import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

/**
 * Test suite for VulnerableServlet - focusing on the Command Injection remediation
 * in the pingHost method.
 *
 * These tests verify that:
 * 1. Valid hostnames and IP addresses are accepted
 * 2. Command injection attempts are blocked
 * 3. Invalid input characters are rejected
 * 4. Null and empty inputs are handled securely
 * 5. Excessively long inputs are rejected
 */
public class VulnerableServletTest {

    private VulnerableServlet servlet;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        servlet = new VulnerableServlet();
    }

    // =========================================================================
    // Tests for pingHost() - Command Injection Remediation
    // =========================================================================

    /**
     * Test that a valid hostname is accepted and processed correctly.
     * This ensures the fix doesn't break legitimate functionality.
     */
    @Test
    public void testPingHost_ValidHostname() throws IOException {
        // Arrange
        when(request.getParameter("host")).thenReturn("example.com");

        // Act
        servlet.pingHost(request, response);

        // Assert
        verify(response).setStatus(202);
        verify(response, never()).sendError(anyInt(), anyString());
        verify(response, never()).sendError(anyInt());
    }

    /**
     * Test that a valid IPv4 address is accepted.
     */
    @Test
    public void testPingHost_ValidIPv4() throws IOException {
        // Arrange
        when(request.getParameter("host")).thenReturn("192.168.1.1");

        // Act
        servlet.pingHost(request, response);

        // Assert
        verify(response).setStatus(202);
        verify(response, never()).sendError(anyInt(), anyString());
    }

    /**
     * Test that a valid IPv6 address is accepted.
     * IPv6 addresses contain colons which are allowed by the validation.
     */
    @Test
    public void testPingHost_ValidIPv6() throws IOException {
        // Arrange
        when(request.getParameter("host")).thenReturn("2001:0db8:85a3:0000:0000:8a2e:0370:7334");

        // Act
        servlet.pingHost(request, response);

        // Assert
        verify(response).setStatus(202);
        verify(response, never()).sendError(anyInt(), anyString());
    }

    /**
     * Test that hostname with hyphens is accepted (valid DNS hostname character).
     */
    @Test
    public void testPingHost_HostnameWithHyphens() throws IOException {
        // Arrange
        when(request.getParameter("host")).thenReturn("my-server.example.com");

        // Act
        servlet.pingHost(request, response);

        // Assert
        verify(response).setStatus(202);
        verify(response, never()).sendError(anyInt(), anyString());
    }

    /**
     * SECURITY TEST: Command injection attempt using semicolon to chain commands.
     * This should be rejected to prevent "ping -c 2 127.0.0.1; cat /etc/passwd".
     */
    @Test
    public void testPingHost_RejectsCommandInjectionWithSemicolon() throws IOException {
        // Arrange - attempt to inject additional command
        when(request.getParameter("host")).thenReturn("127.0.0.1; cat /etc/passwd");

        // Act
        servlet.pingHost(request, response);

        // Assert - should return 400 error, NOT execute the command
        verify(response).sendError(eq(400), eq("Invalid host parameter"));
        verify(response, never()).setStatus(202);
    }

    /**
     * SECURITY TEST: Command injection using pipe operator.
     * Example: "127.0.0.1 | ls -la"
     */
    @Test
    public void testPingHost_RejectsCommandInjectionWithPipe() throws IOException {
        // Arrange
        when(request.getParameter("host")).thenReturn("127.0.0.1 | ls -la");

        // Act
        servlet.pingHost(request, response);

        // Assert
        verify(response).sendError(eq(400), eq("Invalid host parameter"));
        verify(response, never()).setStatus(202);
    }

    /**
     * SECURITY TEST: Command injection using ampersand for background execution.
     * Example: "127.0.0.1 & rm -rf /"
     */
    @Test
    public void testPingHost_RejectsCommandInjectionWithAmpersand() throws IOException {
        // Arrange
        when(request.getParameter("host")).thenReturn("127.0.0.1 & rm -rf /tmp/test");

        // Act
        servlet.pingHost(request, response);

        // Assert
        verify(response).sendError(eq(400), eq("Invalid host parameter"));
        verify(response, never()).setStatus(202);
    }

    /**
     * SECURITY TEST: Command injection using backticks for command substitution.
     * Example: "127.0.0.1 `whoami`"
     */
    @Test
    public void testPingHost_RejectsCommandInjectionWithBackticks() throws IOException {
        // Arrange
        when(request.getParameter("host")).thenReturn("127.0.0.1 `whoami`");

        // Act
        servlet.pingHost(request, response);

        // Assert
        verify(response).sendError(eq(400), eq("Invalid host parameter"));
        verify(response, never()).setStatus(202);
    }

    /**
     * SECURITY TEST: Command injection using $() for command substitution.
     * Example: "127.0.0.1 $(cat /etc/passwd)"
     */
    @Test
    public void testPingHost_RejectsCommandInjectionWithDollarParentheses() throws IOException {
        // Arrange
        when(request.getParameter("host")).thenReturn("127.0.0.1 $(cat /etc/passwd)");

        // Act
        servlet.pingHost(request, response);

        // Assert
        verify(response).sendError(eq(400), eq("Invalid host parameter"));
        verify(response, never()).setStatus(202);
    }

    /**
     * SECURITY TEST: Command injection with newline character.
     * Example: "127.0.0.1\ncat /etc/passwd"
     */
    @Test
    public void testPingHost_RejectsCommandInjectionWithNewline() throws IOException {
        // Arrange
        when(request.getParameter("host")).thenReturn("127.0.0.1\ncat /etc/passwd");

        // Act
        servlet.pingHost(request, response);

        // Assert
        verify(response).sendError(eq(400), eq("Invalid host parameter"));
        verify(response, never()).setStatus(202);
    }

    /**
     * SECURITY TEST: Command injection with spaces (attempting to add extra arguments).
     * Example: "127.0.0.1 -c 1000" could potentially override the ping count.
     */
    @Test
    public void testPingHost_RejectsInputWithSpaces() throws IOException {
        // Arrange
        when(request.getParameter("host")).thenReturn("127.0.0.1 -c 1000");

        // Act
        servlet.pingHost(request, response);

        // Assert
        verify(response).sendError(eq(400), eq("Invalid host parameter"));
        verify(response, never()).setStatus(202);
    }

    /**
     * SECURITY TEST: Special shell characters that should be rejected.
     */
    @Test
    public void testPingHost_RejectsSpecialShellCharacters() throws IOException {
        String[] maliciousInputs = {
            "127.0.0.1;",
            "127.0.0.1'",
            "127.0.0.1\"",
            "127.0.0.1>",
            "127.0.0.1<",
            "127.0.0.1|",
            "127.0.0.1&",
            "127.0.0.1*",
            "127.0.0.1?",
            "127.0.0.1[",
            "127.0.0.1]",
            "127.0.0.1{",
            "127.0.0.1}",
            "127.0.0.1\\",
            "127.0.0.1/"
        };

        for (String maliciousInput : maliciousInputs) {
            // Arrange
            when(request.getParameter("host")).thenReturn(maliciousInput);

            // Act
            servlet.pingHost(request, response);

            // Assert
            verify(response, atLeastOnce()).sendError(eq(400), eq("Invalid host parameter"));
            verify(response, never()).setStatus(202);

            // Reset for next iteration
            reset(response);
        }
    }

    /**
     * Test that null input is rejected with a 400 error.
     */
    @Test
    public void testPingHost_RejectsNullInput() throws IOException {
        // Arrange
        when(request.getParameter("host")).thenReturn(null);

        // Act
        servlet.pingHost(request, response);

        // Assert
        verify(response).sendError(eq(400), eq("Invalid host parameter"));
        verify(response, never()).setStatus(202);
    }

    /**
     * Test that empty string input is rejected.
     */
    @Test
    public void testPingHost_RejectsEmptyString() throws IOException {
        // Arrange
        when(request.getParameter("host")).thenReturn("");

        // Act
        servlet.pingHost(request, response);

        // Assert
        verify(response).sendError(eq(400), eq("Invalid host parameter"));
        verify(response, never()).setStatus(202);
    }

    /**
     * SECURITY TEST: Excessively long input should be rejected to prevent
     * potential DoS or buffer overflow scenarios.
     */
    @Test
    public void testPingHost_RejectsExcessivelyLongInput() throws IOException {
        // Arrange - create a string longer than 255 characters
        StringBuilder longHost = new StringBuilder();
        for (int i = 0; i < 260; i++) {
            longHost.append("a");
        }
        when(request.getParameter("host")).thenReturn(longHost.toString());

        // Act
        servlet.pingHost(request, response);

        // Assert
        verify(response).sendError(eq(400), eq("Host parameter too long"));
        verify(response, never()).setStatus(202);
    }

    /**
     * Test boundary condition: exactly 255 characters (should be accepted).
     */
    @Test
    public void testPingHost_Accepts255CharacterInput() throws IOException {
        // Arrange - create a valid hostname exactly 255 characters long
        StringBuilder host = new StringBuilder();
        for (int i = 0; i < 255; i++) {
            host.append("a");
        }
        when(request.getParameter("host")).thenReturn(host.toString());

        // Act
        servlet.pingHost(request, response);

        // Assert
        verify(response).setStatus(202);
        verify(response, never()).sendError(anyInt(), anyString());
    }

    /**
     * Test boundary condition: exactly 256 characters (should be rejected).
     */
    @Test
    public void testPingHost_Rejects256CharacterInput() throws IOException {
        // Arrange
        StringBuilder host = new StringBuilder();
        for (int i = 0; i < 256; i++) {
            host.append("a");
        }
        when(request.getParameter("host")).thenReturn(host.toString());

        // Act
        servlet.pingHost(request, response);

        // Assert
        verify(response).sendError(eq(400), eq("Host parameter too long"));
        verify(response, never()).setStatus(202);
    }

    /**
     * Test that HSTS security header is set (regression test to ensure
     * the fix doesn't remove existing security controls).
     */
    @Test
    public void testPingHost_SetsSecurityHeaders() throws IOException {
        // Arrange
        when(request.getParameter("host")).thenReturn("example.com");

        // Act
        servlet.pingHost(request, response);

        // Assert - verify security headers are still set
        verify(response).setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
        verify(response).setHeader("X-Content-Type-Options", "nosniff");
    }

    /**
     * SECURITY TEST: Verify that ProcessBuilder pattern prevents shell interpretation.
     * This test documents the expected behavior that the command is NOT executed
     * through /bin/sh, preventing shell metacharacter interpretation.
     *
     * Note: This is a documentation test - actual ProcessBuilder usage can't be
     * easily unit tested without integration tests, but this verifies the security
     * posture by ensuring suspicious inputs are rejected before reaching ProcessBuilder.
     */
    @Test
    public void testPingHost_SecurityPosture_NoShellInterpretation() throws IOException {
        // The fix uses: new ProcessBuilder("ping", "-c", "2", host)
        // instead of: Runtime.exec(new String[] { "/bin/sh", "-c", "ping -c 2 " + host })
        //
        // ProcessBuilder with separate arguments means:
        // - No shell is invoked
        // - host is passed as a literal argument to ping
        // - Shell metacharacters (;, |, &, $, etc.) have no special meaning
        //
        // This test verifies that inputs with shell metacharacters are rejected
        // BEFORE reaching ProcessBuilder, providing defense in depth.

        String[] shellMetacharacters = {";", "|", "&", "$", "`", "\n", ">", "<"};

        for (String metachar : shellMetacharacters) {
            when(request.getParameter("host")).thenReturn("127.0.0.1" + metachar + "echo test");
            servlet.pingHost(request, response);
            verify(response, atLeastOnce()).sendError(eq(400), eq("Invalid host parameter"));
            reset(response);
        }
    }
}
