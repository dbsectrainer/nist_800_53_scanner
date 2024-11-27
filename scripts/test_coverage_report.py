import os
import sys
import subprocess
import xml.etree.ElementTree as ET
from typing import Dict, Any

class TestCoverageReporter:
    """
    Comprehensive test coverage reporting and analysis
    """
    def __init__(self, 
                 project_root: str = None, 
                 output_dir: str = 'coverage_reports'):
        """
        Initialize test coverage reporter
        
        :param project_root: Root directory of the project
        :param output_dir: Directory to store coverage reports
        """
        self.project_root = project_root or os.getcwd()
        self.output_dir = os.path.join(self.project_root, output_dir)
        os.makedirs(self.output_dir, exist_ok=True)
    
    def run_coverage_analysis(self, 
                               source_dirs: list = None, 
                               test_dirs: list = None) -> Dict[str, Any]:
        """
        Run comprehensive test coverage analysis
        
        :param source_dirs: Directories containing source code
        :param test_dirs: Directories containing test files
        :return: Coverage analysis results
        """
        # Default source and test directories if not provided
        source_dirs = source_dirs or ['modules']
        test_dirs = test_dirs or ['tests']
        
        # Prepare coverage command
        coverage_cmd = [
            'coverage', 'run', 
            '-m', 'pytest',
            '--cov=' + ','.join(source_dirs),
            '--cov-report=xml',
            '--cov-report=html:' + os.path.join(self.output_dir, 'html_report')
        ] + test_dirs
        
        # Run coverage analysis
        try:
            subprocess.run(coverage_cmd, check=True, cwd=self.project_root)
        except subprocess.CalledProcessError as e:
            print(f"Coverage analysis failed: {e}")
            return {}
        
        # Parse XML coverage report
        return self._parse_coverage_xml()
    
    def _parse_coverage_xml(self) -> Dict[str, Any]:
        """
        Parse the generated coverage XML report
        
        :return: Parsed coverage metrics
        """
        xml_report_path = os.path.join(self.project_root, 'coverage.xml')
        
        if not os.path.exists(xml_report_path):
            print("Coverage XML report not found")
            return {}
        
        # Parse XML
        tree = ET.parse(xml_report_path)
        root = tree.getroot()
        
        # Extract coverage metrics
        coverage_metrics = {
            'total_lines': 0,
            'covered_lines': 0,
            'modules_coverage': {}
        }
        
        for package in root.findall('.//package'):
            module_name = package.get('name')
            module_lines = 0
            module_covered_lines = 0
            
            for class_elem in package.findall('.//class'):
                for lines in class_elem.findall('.//lines'):
                    for line in lines.findall('.//line'):
                        module_lines += 1
                        coverage_metrics['total_lines'] += 1
                        
                        if line.get('hits') and int(line.get('hits')) > 0:
                            module_covered_lines += 1
                            coverage_metrics['covered_lines'] += 1
            
            # Calculate module coverage
            module_coverage = (module_covered_lines / module_lines * 100) if module_lines > 0 else 0
            coverage_metrics['modules_coverage'][module_name] = module_coverage
        
        # Calculate overall coverage
        coverage_metrics['total_coverage'] = (
            coverage_metrics['covered_lines'] / coverage_metrics['total_lines'] * 100
        ) if coverage_metrics['total_lines'] > 0 else 0
        
        return coverage_metrics
    
    def generate_coverage_report(self, coverage_metrics: Dict[str, Any]) -> None:
        """
        Generate a detailed coverage report
        
        :param coverage_metrics: Coverage analysis results
        """
        report_path = os.path.join(self.output_dir, 'coverage_report.txt')
        
        with open(report_path, 'w') as report_file:
            report_file.write("=== Test Coverage Report ===\n\n")
            report_file.write(f"Total Lines: {coverage_metrics['total_lines']}\n")
            report_file.write(f"Covered Lines: {coverage_metrics['covered_lines']}\n")
            report_file.write(f"Total Coverage: {coverage_metrics['total_coverage']:.2f}%\n\n")
            
            report_file.write("Module Coverage:\n")
            for module, coverage in coverage_metrics['modules_coverage'].items():
                report_file.write(f"{module}: {coverage:.2f}%\n")
            
            # Recommendations based on coverage
            report_file.write("\n=== Recommendations ===\n")
            if coverage_metrics['total_coverage'] < 70:
                report_file.write("- Low test coverage. Consider adding more tests.\n")
            
            print(f"Coverage report generated at {report_path}")
    
    def main(self):
        """
        Main method to run coverage analysis and generate report
        """
        coverage_metrics = self.run_coverage_analysis()
        if coverage_metrics:
            self.generate_coverage_report(coverage_metrics)

if __name__ == '__main__':
    reporter = TestCoverageReporter()
    reporter.main()
