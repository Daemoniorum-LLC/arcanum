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
