// Advanced Dashboard Utilities

(function (window) {
  "use strict";

  // Dashboard Utility Class
  function DashboardUtils() {}

  // Export report to CSV
  DashboardUtils.prototype.exportReportToCSV = function (report, filename) {
    var csvContent = "data:text/csv;charset=utf-8,";
    var headers = [
      "Control Category",
      "Control ID",
      "Description",
      "Compliance Status",
    ];

    csvContent += headers.join(",") + "\r\n";

    var controlCategories = [
      "access_control",
      "audit_logging",
      "network_security",
      "configuration_management",
      "incident_response",
    ];

    controlCategories.forEach(function (category) {
      if (report[category] && report[category].length) {
        report[category].forEach(function (control) {
          var row = [
            category,
            control.control_id || "N/A",
            '"' +
              (control.description || "No Description").replace(/"/g, '""') +
              '"',
            control.compliant ? "Compliant" : "Non-Compliant",
          ];
          csvContent += row.join(",") + "\r\n";
        });
      }
    });

    var encodedUri = encodeURI(csvContent);
    var link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", filename || "nist_compliance_report.csv");

    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // Filter reports by compliance status
  DashboardUtils.prototype.filterReportsByComplianceStatus = function (
    reports,
    status,
  ) {
    return reports.filter(function (report) {
      var totalControls = 0;
      var compliantControls = 0;

      [
        "access_control",
        "audit_logging",
        "network_security",
        "configuration_management",
        "incident_response",
      ].forEach(function (category) {
        if (report[category]) {
          report[category].forEach(function (control) {
            totalControls++;
            if (control.compliant) {
              compliantControls++;
            }
          });
        }
      });

      var compliancePercentage = (compliantControls / totalControls) * 100;

      switch (status) {
        case "fully_compliant":
          return compliancePercentage === 100;
        case "mostly_compliant":
          return compliancePercentage >= 75 && compliancePercentage < 100;
        case "partially_compliant":
          return compliancePercentage >= 50 && compliancePercentage < 75;
        case "non_compliant":
          return compliancePercentage < 50;
        default:
          return true;
      }
    });
  };

  // Search reports by keyword
  DashboardUtils.prototype.searchReports = function (reports, keyword) {
    if (!keyword) return reports;

    return reports.filter(function (report) {
      // Search in metadata
      if (
        report.environment &&
        report.environment.toLowerCase().includes(keyword.toLowerCase())
      ) {
        return true;
      }
      if (
        report.scan_date &&
        report.scan_date.toLowerCase().includes(keyword.toLowerCase())
      ) {
        return true;
      }

      // Search in control details
      var controlCategories = [
        "access_control",
        "audit_logging",
        "network_security",
        "configuration_management",
        "incident_response",
      ];

      return controlCategories.some(function (category) {
        if (report[category]) {
          return report[category].some(function (control) {
            return (
              (control.control_id &&
                control.control_id
                  .toLowerCase()
                  .includes(keyword.toLowerCase())) ||
              (control.description &&
                control.description
                  .toLowerCase()
                  .includes(keyword.toLowerCase()))
            );
          });
        }
        return false;
      });
    });
  };

  // Attach to window for global access
  window.DashboardUtils = DashboardUtils;
})(window);
