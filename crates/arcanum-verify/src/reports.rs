//! Report generation for verification results.

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

use core::fmt;

/// A verification report summarizing test results.
#[derive(Debug, Clone)]
pub struct VerificationReport {
    /// Name of the test suite.
    pub suite_name: String,
    /// Individual test results.
    pub results: Vec<TestResult>,
    /// Overall pass/fail status.
    pub passed: bool,
    /// Timestamp of the report.
    pub timestamp: String,
}

/// Result of a single verification test.
#[derive(Debug, Clone)]
pub struct TestResult {
    /// Name of the test.
    pub name: String,
    /// Whether the test passed.
    pub passed: bool,
    /// Details about the test result.
    pub details: String,
    /// Measured value (if applicable).
    pub measured_value: Option<f64>,
    /// Threshold value (if applicable).
    pub threshold: Option<f64>,
}

impl VerificationReport {
    /// Create a new verification report.
    pub fn new(suite_name: impl Into<String>) -> Self {
        Self {
            suite_name: suite_name.into(),
            results: Vec::new(),
            passed: true,
            timestamp: {
                #[cfg(feature = "std")]
                {
                    format!("{:?}", std::time::SystemTime::now())
                }
                #[cfg(not(feature = "std"))]
                {
                    String::from("(no_std: timestamp unavailable)")
                }
            },
        }
    }

    /// Add a test result to the report.
    pub fn add_result(&mut self, result: TestResult) {
        if !result.passed {
            self.passed = false;
        }
        self.results.push(result);
    }

    /// Generate a summary string.
    pub fn summary(&self) -> String {
        let passed_count = self.results.iter().filter(|r| r.passed).count();
        let total = self.results.len();

        format!(
            "{}: {}/{} tests passed ({})",
            self.suite_name,
            passed_count,
            total,
            if self.passed { "PASS" } else { "FAIL" }
        )
    }

    /// Generate HTML report.
    pub fn to_html(&self) -> String {
        let mut html = String::new();
        html.push_str("<!DOCTYPE html>\n<html>\n<head>\n");
        html.push_str("<title>Arcanum Verification Report</title>\n");
        html.push_str("<style>\n");
        html.push_str("body { font-family: monospace; margin: 2em; }\n");
        html.push_str(".pass { color: green; }\n");
        html.push_str(".fail { color: red; }\n");
        html.push_str("table { border-collapse: collapse; width: 100%; }\n");
        html.push_str("th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }\n");
        html.push_str("</style>\n</head>\n<body>\n");

        html.push_str(&format!("<h1>{}</h1>\n", self.suite_name));
        html.push_str(&format!("<p>Generated: {}</p>\n", self.timestamp));
        html.push_str(&format!(
            "<p class=\"{}\">Status: {}</p>\n",
            if self.passed { "pass" } else { "fail" },
            if self.passed { "PASSED" } else { "FAILED" }
        ));

        html.push_str("<table>\n<tr><th>Test</th><th>Status</th><th>Details</th></tr>\n");
        for result in &self.results {
            html.push_str(&format!(
                "<tr><td>{}</td><td class=\"{}\">{}</td><td>{}</td></tr>\n",
                result.name,
                if result.passed { "pass" } else { "fail" },
                if result.passed { "PASS" } else { "FAIL" },
                result.details
            ));
        }
        html.push_str("</table>\n");

        html.push_str("</body>\n</html>");
        html
    }
}

impl fmt::Display for VerificationReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "╔══════════════════════════════════════════════════════════════╗"
        )?;
        writeln!(f, "║ {} ", self.suite_name)?;
        writeln!(
            f,
            "╠══════════════════════════════════════════════════════════════╣"
        )?;

        for result in &self.results {
            let status = if result.passed { "✓" } else { "✗" };
            writeln!(f, "║ {} {} - {}", status, result.name, result.details)?;
        }

        writeln!(
            f,
            "╠══════════════════════════════════════════════════════════════╣"
        )?;
        writeln!(f, "║ {}", self.summary())?;
        writeln!(
            f,
            "╚══════════════════════════════════════════════════════════════╝"
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a passing TestResult.
    fn passing_result(name: &str) -> TestResult {
        TestResult {
            name: name.into(),
            passed: true,
            details: format!("{} passed", name),
            measured_value: None,
            threshold: None,
        }
    }

    /// Helper to create a failing TestResult.
    fn failing_result(name: &str) -> TestResult {
        TestResult {
            name: name.into(),
            passed: false,
            details: format!("{} failed", name),
            measured_value: None,
            threshold: None,
        }
    }

    #[test]
    fn test_new_report_defaults() {
        let report = VerificationReport::new("AES Test Suite");

        assert_eq!(report.suite_name, "AES Test Suite");
        assert!(report.passed, "new report should default to passed=true");
        assert!(
            report.results.is_empty(),
            "new report should have no results"
        );
        assert!(
            !report.timestamp.is_empty(),
            "timestamp should be populated"
        );
    }

    #[test]
    fn test_add_passing_result_keeps_passed_true() {
        let mut report = VerificationReport::new("Suite");
        report.add_result(passing_result("test_alpha"));

        assert!(
            report.passed,
            "report should remain passed after adding a passing test"
        );
        assert_eq!(report.results.len(), 1);
        assert_eq!(report.results[0].name, "test_alpha");
        assert!(report.results[0].passed);
    }

    #[test]
    fn test_add_failing_result_sets_passed_false() {
        let mut report = VerificationReport::new("Suite");
        report.add_result(passing_result("test_one"));
        report.add_result(failing_result("test_two"));

        assert!(
            !report.passed,
            "report should be failed after adding a failing test"
        );
        assert_eq!(report.results.len(), 2);
        assert!(!report.results[1].passed);
    }

    #[test]
    fn test_summary_all_pass() {
        let mut report = VerificationReport::new("Crypto Suite");
        report.add_result(passing_result("a"));
        report.add_result(passing_result("b"));
        report.add_result(passing_result("c"));

        let summary = report.summary();
        assert!(
            summary.contains("3/3 tests passed"),
            "summary should show 3/3: {}",
            summary
        );
        assert!(
            summary.contains("PASS"),
            "summary should show PASS: {}",
            summary
        );
        assert!(
            summary.contains("Crypto Suite"),
            "summary should contain suite name: {}",
            summary
        );
    }

    #[test]
    fn test_summary_with_failure() {
        let mut report = VerificationReport::new("Hash Suite");
        report.add_result(passing_result("a"));
        report.add_result(failing_result("b"));
        report.add_result(passing_result("c"));

        let summary = report.summary();
        assert!(
            summary.contains("2/3 tests passed"),
            "summary should show 2/3: {}",
            summary
        );
        assert!(
            summary.contains("FAIL"),
            "summary should show FAIL: {}",
            summary
        );
    }

    #[test]
    fn test_to_html_structure() {
        let mut report = VerificationReport::new("HTML Report Suite");
        report.add_result(passing_result("encryption_test"));
        report.add_result(failing_result("decryption_test"));

        let html = report.to_html();

        // Verify HTML document structure
        assert!(html.contains("<!DOCTYPE html>"), "should have DOCTYPE");
        assert!(html.contains("<html>"), "should have html tag");
        assert!(html.contains("</html>"), "should have closing html tag");
        assert!(html.contains("<head>"), "should have head tag");
        assert!(html.contains("<body>"), "should have body tag");
        assert!(html.contains("<table>"), "should have table tag");

        // Verify suite name appears in heading
        assert!(
            html.contains("<h1>HTML Report Suite</h1>"),
            "should contain suite name in h1"
        );

        // Verify test results appear in the table
        assert!(
            html.contains("encryption_test"),
            "should contain passing test name"
        );
        assert!(
            html.contains("decryption_test"),
            "should contain failing test name"
        );

        // Verify pass/fail CSS classes
        assert!(
            html.contains("class=\"pass\""),
            "should have pass CSS class"
        );
        assert!(
            html.contains("class=\"fail\""),
            "should have fail CSS class"
        );

        // Verify PASS/FAIL status text in table rows
        assert!(html.contains(">PASS<"), "should have PASS status text");
        assert!(html.contains(">FAIL<"), "should have FAIL status text");
    }

    #[test]
    fn test_display_impl_box_drawing() {
        let mut report = VerificationReport::new("Display Suite");
        report.add_result(passing_result("test_one"));
        report.add_result(failing_result("test_two"));

        let output = format!("{}", report);

        // Verify box drawing characters are present
        assert!(output.contains('╔'), "should contain top-left corner");
        assert!(output.contains('╗'), "should contain top-right corner");
        assert!(output.contains('╠'), "should contain left T-junction");
        assert!(output.contains('╣'), "should contain right T-junction");
        assert!(output.contains('╚'), "should contain bottom-left corner");
        assert!(output.contains('╝'), "should contain bottom-right corner");
        assert!(output.contains('║'), "should contain vertical bar");

        // Verify suite name appears
        assert!(
            output.contains("Display Suite"),
            "should contain suite name"
        );

        // Verify test results with status indicators
        assert!(output.contains("✓"), "should contain check mark for pass");
        assert!(output.contains("✗"), "should contain X mark for fail");
        assert!(
            output.contains("test_one"),
            "should contain first test name"
        );
        assert!(
            output.contains("test_two"),
            "should contain second test name"
        );

        // Verify summary is included
        assert!(
            output.contains("1/2 tests passed"),
            "should contain summary: {}",
            output
        );
    }

    #[test]
    fn test_result_with_measured_value_and_threshold() {
        let result = TestResult {
            name: "entropy_test".into(),
            passed: true,
            details: "entropy within acceptable range".into(),
            measured_value: Some(7.98),
            threshold: Some(7.5),
        };

        assert_eq!(result.name, "entropy_test");
        assert!(result.passed);
        assert_eq!(result.measured_value, Some(7.98));
        assert_eq!(result.threshold, Some(7.5));

        // Verify measured value exceeds threshold (semantic assertion)
        let measured = result.measured_value.unwrap();
        let thresh = result.threshold.unwrap();
        assert!(
            measured > thresh,
            "measured value {} should exceed threshold {}",
            measured,
            thresh
        );

        // Verify a result without measured_value/threshold
        let simple_result = passing_result("simple");
        assert!(
            simple_result.measured_value.is_none(),
            "simple result should have no measured_value"
        );
        assert!(
            simple_result.threshold.is_none(),
            "simple result should have no threshold"
        );
    }
}
