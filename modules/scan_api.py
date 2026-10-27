from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from .authentication import AuthenticationManager
from .input_validator import InputValidator
from .encryption import SecureDataHandler, SecureKeyStorage
from .monitoring import SystemMonitor
from .report_versioning import ReportVersionManager

import logging
import os
import time
import traceback

class ScanAPI:
    def __init__(self, 
                 auth_manager=None, 
                 rate_limiter=None, 
                 encryption_handler=None,
                 monitoring_handler=None,
                 report_manager=None):
        """
        Initialize Scan API with optional dependency injection.
        
        Args:
            auth_manager: Authentication manager
            rate_limiter: Rate limiting manager
            encryption_handler: Data encryption handler
            monitoring_handler: System monitoring handler
            report_manager: Report versioning manager
        """
        self.app = Flask(__name__)
        
        # Initialize dependencies
        self.auth_manager = auth_manager or AuthenticationManager()

        # Per-route limits (flask-limiter); an injected RateLimiter adds a
        # per-client-IP check on every request on top of them.
        self.limiter = Limiter(
            get_remote_address,
            app=self.app,
            default_limits=["100 per day", "30 per hour"],
            storage_uri="memory://",
        )
        self.rate_limiter = rate_limiter
        if self.rate_limiter is not None:
            self.app.before_request(self._enforce_injected_rate_limit)

        self.encryption_handler = encryption_handler or SecureDataHandler(
            SecureKeyStorage(os.environ.get("NIST_SCANNER_MASTER_KEY_PATH", "master.key"))
        )
        self.monitoring_handler = monitoring_handler or SystemMonitor()
        self.report_manager = report_manager or ReportVersionManager()
        
        # Configure logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
        # Setup routes
        self._setup_routes()

    def _enforce_injected_rate_limit(self):  # noqa: ANN202 - Flask before_request hook
        """Apply the injected RateLimiter's "default" limit per client IP."""
        is_limited, retry_after = self.rate_limiter.is_rate_limited("default", get_remote_address())
        if is_limited:
            response = jsonify({"error": "Rate limit exceeded"})
            response.status_code = 429
            response.headers["Retry-After"] = str(int(retry_after or 0))
            return response
        return None

    def _setup_routes(self):
        """
        Configure API routes with authentication and rate limiting.
        """
        @self.app.route('/api/scan', methods=['POST'])
        @self.limiter.limit("10 per minute")
        def initiate_scan():
            try:
                # Validate API key
                api_key = request.headers.get('X-API-Key')
                user = self.auth_manager.validate_api_key(api_key)
                if not user:
                    return jsonify({"error": "Invalid API key"}), 401
                
                # Validate input
                scan_params = request.get_json(silent=True)
                validation = InputValidator.validate_scan_parameters(scan_params)
                if not validation["valid"]:
                    return jsonify({"error": "Invalid scan parameters", "details": validation["errors"]}), 400
                
                # Sanitize input
                sanitized_params = InputValidator.sanitize_input(scan_params)
                
                # Perform scan (placeholder for actual scanning logic)
                scan_results = self._perform_scan(sanitized_params)
                
                # Encrypt sensitive results
                encrypted_results = self.encryption_handler.encrypt_data(scan_results)
                
                # Create versioned report
                report_path = self.report_manager.create_report_version(
                    {"results": encrypted_results},
                    metadata={"user": user["username"]}
                )
                report_id = os.path.splitext(os.path.basename(report_path))[0]
                
                return jsonify({
                    "report_id": report_id,
                    "status": "completed"
                }), 200
            
            except Exception as e:
                self.logger.error(f"Scan error: {str(e)}")
                self.logger.error(traceback.format_exc())
                return jsonify({"error": "Internal server error"}), 500

        @self.app.route('/api/reports', methods=['GET'])
        @self.limiter.limit("20 per minute")
        def list_reports():
            try:
                # Validate API key
                api_key = request.headers.get('X-API-Key')
                user = self.auth_manager.validate_api_key(api_key)
                if not user:
                    return jsonify({"error": "Invalid API key"}), 401
                
                # Get reports (could filter by user role in future)
                reports = self.report_manager.get_report_versions()
                return jsonify(reports), 200
            
            except Exception as e:
                self.logger.error(f"Report listing error: {str(e)}")
                return jsonify({"error": "Internal server error"}), 500

        @self.app.route("/api/report/<report_id>", methods=["GET"])
        @self.limiter.limit("20 per minute")
        def get_report(report_id: str):  # noqa: ANN202 - Flask view
            try:
                api_key = request.headers.get("X-API-Key")
                if not self.auth_manager.validate_api_key(api_key):
                    return jsonify({"error": "Invalid API key"}), 401

                report = self.report_manager.get_report_by_id(report_id)
                if report is None:
                    return jsonify({"error": "Report not found"}), 404
                return jsonify(report), 200

            except Exception as e:
                self.logger.error(f"Report retrieval error: {str(e)}")
                return jsonify({"error": "Internal server error"}), 500

    def _perform_scan(self, params):
        """
        Placeholder for actual scanning logic.
        
        Args:
            params: Sanitized scan parameters
        
        Returns:
            Scan results dictionary
        """
        # TODO: Implement actual scanning logic
        return {
            "target": params.get('target', 'unknown'),
            "scan_type": params.get('scan_type', 'default'),
            "timestamp": time.time(),
            "findings": []  # Placeholder for actual scan findings
        }

    def run(self, host='0.0.0.0', port=5001, debug=False):
        """
        Run the Flask application.
        
        Args:
            host: Binding host
            port: Binding port
            debug: Debug mode flag
        """
        # Start system monitoring
        self.monitoring_handler.start_monitoring()
        
        try:
            self.app.run(host=host, port=port, debug=debug)
        finally:
            # Ensure monitoring is stopped when app closes
            self.monitoring_handler.stop_monitoring()
