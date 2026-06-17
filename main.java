package com.example.training;
 
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Arrays;
import java.util.List;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
 
/**
* VulnerableServlet
*
* Training sample for Checkmarx SAST. Targets exactly five findings:
*   1. SQL_Injection            [EXPLOITABLE]      searchProducts()
*   2. Command_Injection        [EXPLOITABLE]      pingHost()
*   3. Reflected_XSS            [EXPLOITABLE]      renderSearchPage()
*   4. SQL_Injection            [NOT EXPLOITABLE]  listEmployeesByDepartment()
*   5. Relative_Path_Traversal  [NOT EXPLOITABLE]  fetchReport()
*
* Cleanups vs the previous version, to remove the extra findings:
*   - No DB row content written to the response  (suppresses Stored_XSS)
*   - No file contents written to the response   (suppresses Stored_XSS)
*   - User input not reflected outside the XSS endpoint (suppresses extra Reflected_XSS)
*   - HSTS header set on every response          (suppresses Missing_HSTS_Header)
*   - Search/category-style parameters instead of identifier/role-style
*     (reduces Parameter_Tampering surface)
*
* For challenge content only. Do not deploy.
*/
public class VulnerableServlet extends HttpServlet {
 
    private static final String DB_URL = "jdbc:mysql://localhost:3306/appdb";
 
    private static final List<String> ALLOWED_DEPARTMENTS = Arrays.asList(
        "engineering",
        "sales",
        "support"
    );
 
    private static final List<String> ALLOWED_REPORTS = Arrays.asList(
        "monthly_report.txt",
        "quarterly_report.txt",
        "annual_report.txt"
    );
 
    /** Sets HSTS and content-type-options on every response. */
    private void addSecurityHeaders(HttpServletResponse response) {
        response.setHeader("Strict-Transport-Security",
                           "max-age=31536000; includeSubDomains");
        response.setHeader("X-Content-Type-Options", "nosniff");
    }
 
    // =====================================================================
    // VULNERABILITY 1 - SQL_Injection  [EXPLOITABLE]
    // CWE-89
    //
    // The 'name' parameter flows directly into a LIKE clause via string
    // concatenation. Statement.executeQuery is the sink. Classic SQLi.
    // No DB row content is written back to the response, so this flow
    // does not also trigger a Stored_XSS finding.
    // =====================================================================
    public void searchProducts(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
 
        addSecurityHeaders(response);
 
        String name = request.getParameter("name");
        try (Connection conn = DriverManager.getConnection(DB_URL);
             Statement stmt = conn.createStatement()) {
 
            String sql = "SELECT id FROM products WHERE name LIKE '%" + name + "%'";
            stmt.executeQuery(sql);
        } catch (SQLException e) {
            response.sendError(500);
            return;
        }
        response.setStatus(200);
    }
 
    // =====================================================================
    // VULNERABILITY 2 - Command_Injection  [EXPLOITABLE]
    // CWE-78
    //
    // The 'host' parameter is appended into a shell command and passed
    // to Runtime.exec via /bin/sh -c. Shell metacharacters allow
    // arbitrary command execution. The host value is not reflected back
    // to the response, so this flow does not also trigger Reflected_XSS.
    // =====================================================================
    public void pingHost(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
 
        addSecurityHeaders(response);
 
        String host = request.getParameter("host");
        String[] cmd = { "/bin/sh", "-c", "ping -c 2 " + host };
        Runtime.getRuntime().exec(cmd);
        response.setStatus(202);
    }
 
    // =====================================================================
    // VULNERABILITY 3 - Reflected_XSS  [EXPLOITABLE]
    // CWE-79
    //
    // The 'q' parameter is written into an HTML response with no HTML
    // entity encoding. Reflected XSS sink is PrintWriter.println on a
    // text/html response.
    // =====================================================================
    public void renderSearchPage(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
 
        addSecurityHeaders(response);
 
        String query = request.getParameter("q");
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        out.println("<h2>You searched for: " + query + "</h2>");
        out.println("</body></html>");
    }
 
    // =====================================================================
    // VULNERABILITY 4 - SQL_Injection  [NOT EXPLOITABLE]
    // CWE-89
    //
    // The 'department' parameter is checked against a strict allow-list
    // of three string constants before it is concatenated into the SQL
    // statement. The taint is fully neutralised before reaching the sink,
    // but Checkmarx data flow may still report this finding because the
    // List.contains check is not always recognised as a sanitiser.
    // Triage: Not Exploitable.
    // =====================================================================
    public void listEmployeesByDepartment(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
 
        addSecurityHeaders(response);
 
        String department = request.getParameter("department");
        if (department == null || !ALLOWED_DEPARTMENTS.contains(department)) {
            response.sendError(400, "Invalid department");
            return;
        }
 
        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement stmt = conn.prepareStatement(
                 "SELECT id FROM employees WHERE department = ?")) {

            // Use parameterized query to prevent SQL injection
            stmt.setString(1, department);
            stmt.executeQuery();
        } catch (SQLException e) {
            response.sendError(500);
            return;
        }
        response.setStatus(200);
    }
 
    // =====================================================================
    // VULNERABILITY 5 - Relative_Path_Traversal  [NOT EXPLOITABLE]
    // CWE-22
    //
    // The 'file' parameter is tainted, but its value is checked against
    // a hard-coded whitelist of three filenames. The whitelist excludes
    // any separator or traversal sequence by definition. The sink is
    // reached only with one of three constant values.
    // File contents are read but discarded, so this flow does not also
    // trigger a Stored_XSS finding.
    // Triage: Not Exploitable.
    // =====================================================================
    public void fetchReport(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
 
        addSecurityHeaders(response);
 
        String fileParam = request.getParameter("file");
        if (fileParam == null || !ALLOWED_REPORTS.contains(fileParam)) {
            response.sendError(403, "File not allowed");
            return;
        }
 
        File file = new File("/var/app/reports/" + fileParam);
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] buffer = new byte[4096];
            while (fis.read(buffer) != -1) {
                // bytes intentionally discarded; do not write to response
            }
        }
        response.setStatus(200);
    }
}
