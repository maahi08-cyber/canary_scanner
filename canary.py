#!/usr/bin/env python3
"""
Canary Scanner - Enhanced with Validation & Context (Phase 4 MVP)
=================================================================
Production-ready secret detection tool with validation client, context awareness,
and CI/CD integration.

Version: 4.0.0 (Phase 4: Enterprise Enhancements)
Author: Security Engineering Team
License: MIT
"""

import argparse
import asyncio
import json
import os
import sys
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
import httpx # For calling dashboard API
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.text import Text

# Import scanner components (assuming they are in the 'scanner' package)
try:
    from scanner.core import Scanner, Finding # Use the modified core.py
    from scanner.patterns import load_patterns
    from scanner.validators import validation_client # Import the validation client
except ImportError as e:
    print(f"Error importing scanner components: {e}. Ensure scanner package is installed or in PYTHONPATH.", file=sys.stderr)
    sys.exit(2)

# Configure logging
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Rich console
console = Console()

# Version information
__version__ = "4.0.0"
__phase__ = "Enterprise Enhancements"

class CanaryScannerCLI:
    """
    Enhanced Canary Scanner CLI with validation and dashboard integration.
    """

    def __init__(self, patterns_file: str = "patterns.yml"):
        self.patterns_file = patterns_file
        self.scanner: Optional[Scanner] = None
        self.patterns = []
        self.scan_start_time: Optional[datetime] = None
        self.repository_name: Optional[str] = None
        self.commit_hash: Optional[str] = None
        self.branch: Optional[str] = None
        self._initialize_scanner()

    def _initialize_scanner(self):
        """Initialize the scanner engine with patterns."""
        try:
            self.patterns = load_patterns(self.patterns_file)
            self.scanner = Scanner(self.patterns)
            logger.info(f"✅ Initialized scanner with {len(self.patterns)} patterns from '{self.patterns_file}'")
        except FileNotFoundError:
             logger.error(f"❌ Pattern file '{self.patterns_file}' not found.")
             raise
        except Exception as e:
            logger.error(f"❌ Failed to initialize scanner: {e}", exc_info=True)
            raise RuntimeError(f"Scanner initialization failed: {e}") from e

    def configure_repo_context(self, repository: Optional[str], commit: Optional[str] = None, branch: Optional[str] = None):
        """Configure repository context, often from CI environment variables."""
        self.repository_name = repository
        self.commit_hash = commit or os.getenv('GITHUB_SHA', 'unknown_commit')
        self.branch = branch or os.getenv('GITHUB_REF_NAME', 'unknown_branch')
        if repository:
             logger.info(f"📁 Repository context set: {repository} ({self.branch} @ {self.commit_hash[:7]})")

    async def scan_target(self, target_path: str, **options) -> Dict[str, Any]:
        """
        Scan a target path, optionally validate findings, and return results.
        """
        if not self.scanner:
             raise RuntimeError("Scanner not initialized. Cannot scan.")
        self.scan_start_time = datetime.utcnow()
        initial_findings: List[Finding] = []
        scan_type = "unknown"
        logger.info(f"Starting scan for target: {target_path}")

        try:
            # --- 1. Perform Initial Scan ---
            if os.path.isfile(target_path):
                initial_findings = list(self.scanner.scan_file(target_path))
                scan_type = "file"
            elif os.path.isdir(target_path):
                initial_findings = self.scanner.scan_directory(target_path)
                scan_type = "directory"
            else:
                raise FileNotFoundError(f"Target path does not exist or is not accessible: {target_path}")

            logger.info(f"Initial scan found {len(initial_findings)} potential secrets.")

            # --- 2. Perform Validation (if requested) ---
            validated_findings_data = [] # This will hold the final list
            validation_stats = {"requested": 0, "completed": 0, "errors": 0}

            if options.get('validate') and initial_findings:
                 logger.info(f"🔬 Starting validation for {len(initial_findings)} findings...")
                 validation_tasks = {} # Store task for each finding index

                 for i, finding in enumerate(initial_findings):
                     # Determine if validation should be attempted based on policy (MVP: High/Medium)
                     # In full impl: Load policy from config/validation_policies.yml
                     should_validate = finding.confidence in ["High", "Medium"]

                     if should_validate:
                         validation_stats["requested"] += 1
                         # Use finding.matched_string (raw secret) for validation
                         task = validation_client.submit_for_validation(finding.rule_id, finding.matched_string)
                         validation_tasks[i] = task
                     # else: # No need for placeholder task if not validating

                 # Execute validation tasks concurrently
                 if validation_tasks:
                     results = await asyncio.gather(*validation_tasks.values(), return_exceptions=True)
                     validation_results_map = dict(zip(validation_tasks.keys(), results))
                     logger.info("✅ Validation calls completed.")
                 else:
                     validation_results_map = {}

                 # Combine initial findings with validation results
                 for i, finding in enumerate(initial_findings):
                      finding_data = self._finding_to_dict(finding, options.get('verbose', False))
                      if i in validation_results_map:
                          validation_result = validation_results_map[i]
                          if isinstance(validation_result, Exception):
                               logger.error(f"Validation task failed for finding {i} ({finding.rule_id}): {validation_result}")
                               finding_data["validation_status"] = "error"
                               validation_stats["errors"] += 1
                          elif isinstance(validation_result, dict):
                               finding_data["validation_status"] = validation_result.get("status", "error")
                               if finding_data["validation_status"] == "error": validation_stats["errors"] += 1
                               validation_stats["completed"] += 1
                          else: # Should not happen
                               finding_data["validation_status"] = "error"
                               validation_stats["errors"] += 1
                      else:
                          finding_data["validation_status"] = "unvalidated" # Not submitted

                      validated_findings_data.append(finding_data)

            else:
                 # If not validating, just format initial findings with 'unvalidated' status
                 validated_findings_data = [self._finding_to_dict(f, options.get('verbose', False)) for f in initial_findings]

            # --- 3. Generate Final Results ---
            scan_duration = (datetime.utcnow() - self.scan_start_time).total_seconds()
            final_results = self._generate_scan_results(
                validated_findings_data, # Use the list with validation statuses
                target_path, scan_type, scan_duration, validation_stats, **options
            )
            logger.info(f"✅ Scan finished: {len(validated_findings_data)} findings reported in {scan_duration:.2f}s.")
            return final_results

        except Exception as e:
            logger.error(f"❌ Scan failed catastrophically for {target_path}: {e}", exc_info=True)
            return self._generate_error_results(target_path, str(e))

    def _finding_to_dict(self, finding: Finding, verbose: bool = False) -> Dict[str, Any]:
         """Converts a Finding object to a dictionary for JSON/API, including context."""
         if not self.scanner: return {} # Should not happen if initialized
         file_context = self.scanner._determine_context(finding.file_path)
         return {
            "file_path": finding.file_path,
            "line_number": finding.line_number,
            "rule_id": finding.rule_id,
            "description": finding.description,
            "confidence": finding.confidence, # Note: This is the context-adjusted confidence
            "secret_preview": self._mask_secret(finding.matched_string, verbose),
            "matched_string": finding.matched_string,
            "context": file_context,
            "validation_status": "unvalidated" # Default, will be updated if validation runs
         }

    def _generate_scan_results(self, findings_data: List[Dict], target_path: str,
                             scan_type: str, scan_duration: float, validation_stats: Dict, **options) -> Dict[str, Any]:
        """Generate final results structure including validation stats."""
        severity = {"critical": 0, "medium": 0, "low": 0}
        active_findings_count = 0
        for f_data in findings_data:
            if f_data.get('validation_status') == 'active': active_findings_count += 1
            conf = f_data.get('confidence', 'Low')
            if conf == 'High': severity['critical'] += 1
            elif conf == 'Medium': severity['medium'] += 1
            else: severity['low'] += 1

        scanner_stats = self.scanner.get_scan_statistics() if self.scanner else {}

        results = {
            "scan_metadata": {
                "scanner_version": __version__,
                "scan_timestamp": self.scan_start_time.isoformat() + "Z" if self.scan_start_time else None,
                "target_path": str(target_path),
                "scan_type": scan_type,
                "scan_duration_seconds": round(scan_duration, 2),
                "total_findings_reported": len(findings_data),
                "active_findings_count": active_findings_count,
                "patterns_loaded": len(self.patterns),
                "validation_stats": validation_stats, # Add validation stats
            },
            "repository_context": {
                "repository_name": self.repository_name,
                "commit_hash": self.commit_hash,
                "branch": self.branch
            } if self.repository_name else None,
            "severity_breakdown": severity, # Based on initial/contextual confidence
            "scanner_statistics": scanner_stats,
            "findings": findings_data, # Includes context and validation status
            "ci_metadata": {
                 "exit_code": self._calculate_exit_code(findings_data, options.get('fail_on', 'any'))
            }
        }
        return results

    def _generate_error_results(self, target_path: str, error_message: str) -> Dict[str, Any]:
        """Generate JSON for scan errors."""
        return {
            "scan_metadata": {
                "scanner_version": __version__,
                "scan_timestamp": datetime.utcnow().isoformat() + "Z",
                "target_path": str(target_path),
                "status": "failed",
                "error": error_message
            },
            "findings": [],
            "ci_metadata": {"exit_code": 2} # Indicate configuration/runtime error
        }

    def _mask_secret(self, secret: str, verbose: bool = False) -> str:
        """Mask secret for safe display."""
        if verbose: return secret
        if len(secret) <= 8: return "*" * len(secret)
        return secret[:4] + "*" * (len(secret) - 8) + secret[-4:]

    def _calculate_exit_code(self, findings_data: List[Dict], fail_on: str) -> int:
        """Calculate exit code based on ACTIVE findings and threshold."""
        active_findings = [f for f in findings_data if f.get('validation_status') == 'active']
        if not active_findings: return 0

        if fail_on == "any": return 1
        # fail_on critical/high/medium relates to confidence level of ACTIVE secrets
        if fail_on == "critical" and any(f['confidence'] == "High" for f in active_findings): return 1
        if fail_on == "high" and any(f['confidence'] in ["High"] for f in active_findings): return 1 # Adjusted: Only High for 'high'
        if fail_on == "medium" and any(f['confidence'] in ["High", "Medium"] for f in active_findings): return 1
        return 0 # Pass if active secrets are below threshold

    async def send_to_dashboard(self, results_payload: Dict[str, Any], dashboard_url: str) -> bool:
        """Sends the final results JSON to the dashboard API."""
        if not dashboard_url:
            logger.debug("No dashboard URL provided, skipping submission.")
            return True
        api_endpoint = f"{dashboard_url.rstrip('/')}/api/v1/scan"
        logger.info(f"➡️ Attempting to send validated results to {api_endpoint}")

        # Construct payload (already contains validation status)
        payload = {
            "repository_name": results_payload.get("repository_context", {}).get("repository_name"),
            "commit_hash": results_payload.get("repository_context", {}).get("commit_hash"),
            "branch": results_payload.get("repository_context", {}).get("branch"),
            "scan_metadata": results_payload.get("scan_metadata"),
            "findings": results_payload.get("findings")
        }
        if not payload["repository_name"] or not payload["commit_hash"]:
             logger.error("❌ Missing repository context for dashboard submission.")
             return False

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(api_endpoint, json=payload, headers={"Content-Type": "application/json"})
                response.raise_for_status()
            dashboard_response = response.json()
            logger.info(f"✅ Successfully sent results to dashboard. Scan ID: {dashboard_response.get('scan_id')}")
            if dashboard_response.get('results_url'):
                 logger.info(f"🔗 View Results: {dashboard_response['results_url']}")
            return True
        except httpx.RequestError as e: logger.error(f"❌ Network error sending to dashboard: {e}")
        except httpx.HTTPStatusError as e: logger.error(f"❌ Dashboard submission failed: {e.response.status_code} - {e.response.text}")
        except Exception as e: logger.error(f"❌ Unexpected error sending to dashboard: {e}", exc_info=True)
        return False

    def display_console_results(self, results: Dict[str, Any], ci_mode: bool = False):
        """Displays results (rich or compact), including validation status."""
        scan_metadata = results.get("scan_metadata", {})
        if scan_metadata.get("status") == "failed":
             console.print(f"❌ [red]Scan Failed: {scan_metadata.get('error')}[/red]")
             return

        if ci_mode: self._display_ci_results(results)
        else: self._display_rich_results(results)

    def _display_ci_results(self, results: Dict[str, Any]):
        """Compact CI output showing active findings."""
        findings_data = results.get("findings", [])
        active_count = results.get("scan_metadata", {}).get("active_findings_count", 0)
        total_count = results.get("scan_metadata", {}).get("total_findings_reported", 0)
        validation_stats = results.get("scan_metadata", {}).get("validation_stats", {})

        if active_count == 0:
            console.print(f"✅ SECURITY SCAN PASSED: No active secrets detected ({total_count} inactive/unvalidated potential findings).")
            if validation_stats.get("errors", 0) > 0:
                 console.print(f"   ⚠️  ({validation_stats['errors']} validation errors occurred)")
            return

        console.print(f"🚨 SECURITY SCAN FAILED: Found {active_count} active secret(s) ({total_count} total potential).")
        # List only active findings in CI for brevity
        active_findings = [f for f in findings_data if f.get('validation_status') == 'active']
        for i, finding in enumerate(active_findings[:10], 1): # Show max 10 active
             prio = "🔴 Crit" if finding['confidence'] == 'High' else "🟡 Med" if finding['confidence'] == 'Medium' else "🔵 Low"
             ctx = f"({finding.get('context', 'n/a')})"
             console.print(f"  {i}. 🔥 ACTIVE {prio} - {finding['file_path']}:{finding['line_number']} {ctx}")
             console.print(f"     Rule: {finding['rule_id']} - {finding['description']}")
             console.print(f"     Secret: {finding['secret_preview']}")
        if len(active_findings) > 10:
             console.print(f"  ... and {len(active_findings) - 10} more active findings.")
        if validation_stats.get("errors", 0) > 0:
            console.print(f"   ⚠️  ({validation_stats['errors']} validation errors occurred)")


    def _display_rich_results(self, results: Dict[str, Any]):
        """Rich console output including validation status and context."""
        findings_data = results.get("findings", [])
        scan_metadata = results.get("scan_metadata", {})
        active_count = scan_metadata.get("active_findings_count", 0)
        total_count = scan_metadata.get("total_findings_reported", 0)
        validation_stats = scan_metadata.get("validation_stats", {})

        # Header
        if active_count > 0:
            title = f"🚨 SECURITY ALERT: {active_count} Active Secret(s) Detected! ({total_count} total potential)"
            header_style = "red"
        elif total_count > 0:
             title = f"⚠️ Security Scan Complete: {total_count} potential secrets found (0 Active)"
             header_style = "yellow"
        else:
            title = "✅ Security Scan Complete: No Secrets Detected!"
            header_style = "green"
        console.print(Panel(title, style=header_style, expand=False))

        if total_count == 0:
            console.print("🎉 [green]Congratulations! Your code is clean and secure.[/green]")
            return

        # Findings table
        table = Table(show_header=True, header_style="bold magenta", title=f"Found {total_count} potential secrets")
        table.add_column("Priority", style="bold", width=10)
        table.add_column("Status", style="dim", width=12)
        table.add_column("Context", style="dim", width=8)
        table.add_column("File", style="cyan", width=30)
        table.add_column("Line", justify="right", width=5)
        table.add_column("Rule ID", style="blue", width=15)
        table.add_column("Description", width=30)
        table.add_column("Secret Preview", style="red", width=20)

        def sort_key(f): # Sort by active, then confidence
             active_prio = 0 if f.get('validation_status') == 'active' else 1
             conf_prio = {'High': 0, 'Medium': 1, 'Low': 2}.get(f.get('confidence'), 3)
             return (active_prio, conf_prio, f.get('file_path'), f.get('line_number'))

        for finding in sorted(findings_data, key=sort_key):
             prio = finding.get('confidence', 'Low')
             priority_text = f"[{'red' if prio == 'High' else 'yellow' if prio == 'Medium' else 'blue'}] {prio.upper()}[/]"

             val_status = finding.get('validation_status', 'n/a')
             status_style, status_icon = "dim", "❓"
             if val_status == 'active': status_style, status_icon = "bold red", "🔥"
             elif val_status == 'inactive': status_style, status_icon = "dim green", "✔️"
             elif val_status == 'error': status_style, status_icon = "yellow", "⚠️"
             elif val_status == 'unsupported': status_style, status_icon = "dim", "🚫"
             status_text = f"[{status_style}]{status_icon} {val_status.capitalize()}[/]"

             ctx = finding.get('context', 'n/a')
             context_text = f"[{'dim' if ctx != 'code' else 'default'}]{ctx}[/]"

             fp = finding['file_path']
             file_path_display = f"...{fp[-27:]}" if len(fp) > 30 else fp
             desc = finding['description']
             desc_display = f"{desc[:27]}..." if len(desc) > 30 else desc

             table.add_row(
                 priority_text, status_text, context_text,
                 file_path_display, str(finding['line_number']),
                 finding['rule_id'], desc_display, finding['secret_preview']
             )

        console.print(table)

        # Validation Summary
        if validation_stats.get("requested", 0) > 0:
             console.print(
                 f"🔬 Validation: {validation_stats['completed']}/{validation_stats['requested']} completed. "
                 f"{active_count} active. {validation_stats['errors']} errors.", style="dim"
             )

        # Action items
        if active_count > 0:
             console.print(Panel(
                """⚠️ IMMEDIATE ACTION REQUIRED on 🔥 ACTIVE secrets:
1. 🛑 DO NOT MERGE this code.
2. 🔄 Rotate exposed credentials immediately.
3. 🗑️ Remove secrets from source code & history.
4. 🔐 Use environment variables or secure vaults.""",
                title="🔥 Active Secret Response", style="bold red"
             ))
        elif total_count > 0:
             console.print(Panel(
                """ℹ️ Please review potential secrets found:
1. Check context (test/example/docs) for relevance.
2. Confirm if inactive/unvalidated secrets pose any risk.
3. Consider removing unnecessary secrets even if inactive.""",
                title="Review Potential Secrets", style="yellow"
             ))

        # Dashboard link
        dashboard_info = results.get("dashboard_info")
        if dashboard_info and dashboard_info.get("results_url"):
            console.print(f"\n🔗 [blue]View detailed results in dashboard: {dashboard_info['results_url']}[/blue]")


def create_argument_parser() -> argparse.ArgumentParser:
    """Configures the argument parser for Phase 4."""
    parser = argparse.ArgumentParser(
        description=f"Canary Scanner v{__version__}: {__phase__}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan current directory, validate secrets via http://localhost:8001
  python canary.py . --validate

  # CI Mode: Scan, validate, fail on active High/Medium, report to dashboard
  python canary.py . --ci-mode --validate --fail-on medium \\
    --report-url $DASHBOARD_URL --repository $GITHUB_REPOSITORY \\
    --commit $GITHUB_SHA --branch $GITHUB_REF_NAME

  # Scan, ignoring findings in test/example context
  python canary.py /path/to/project --filter-context test,example
        """)

    parser.add_argument("path", help="File or directory path to scan")
    parser.add_argument("--output-json", action="store_true", help="Output results in JSON format")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show full secret values (⚠️ use caution)")
    parser.add_argument("--ci-mode", action="store_true", help="CI/CD optimized mode (affects console output)")
    parser.add_argument("--fail-on", choices=["any", "critical", "high", "medium"], default="medium",
                       help="Set failure threshold based on ACTIVE secrets confidence (default: %(default)s)")
    parser.add_argument("--patterns-file", default="patterns.yml", help="Path to patterns file")

    # --- Phase 4 Arguments ---
    parser.add_argument("--validate", action="store_true", help="Enable secret validation via validation service")
    parser.add_argument("--validation-url", default=os.getenv("VALIDATION_SERVICE_URL", "http://localhost:8001"),
                        help="URL of the validation service (or use env var VALIDATION_SERVICE_URL)")
    parser.add_argument("--validation-api-key", default=os.getenv("VALIDATION_SERVICE_API_KEY"),
                        help="API key for validation service (or use env var VALIDATION_SERVICE_API_KEY)")
    parser.add_argument("--filter-context", help="Comma-separated context types to ignore (e.g., 'test,docs')")
    # --- End Phase 4 ---

    parser.add_argument("--report-url", default=os.getenv("DASHBOARD_API_URL"),
                        help="Dashboard API URL for reporting results (or use env var DASHBOARD_API_URL)")
    parser.add_argument("--repository", default=os.getenv("GITHUB_REPOSITORY"),
                        help="Repo name (org/repo format) for context (or use env var GITHUB_REPOSITORY)")
    parser.add_argument("--commit", default=os.getenv("GITHUB_SHA"), help="Commit hash (or use env var GITHUB_SHA)")
    parser.add_argument("--branch", default=os.getenv("GITHUB_REF_NAME"), help="Branch name (or use env var GITHUB_REF_NAME)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__} ({__phase__})")

    return parser

async def main() -> int:
    """Main entry point for Phase 4 CLI."""
    parser = create_argument_parser()
    args = parser.parse_args()

    # Configure validation client early if needed
    if args.validate:
        validation_client.base_url = args.validation_url
        validation_client.api_key = args.validation_api_key
        logger.info(f"Validation enabled. Service URL: {validation_client.base_url}")

    exit_code = 0
    results = {}
    try:
        if not os.path.exists(args.path):
            console.print(f"❌ [red]Error: Path does not exist: {args.path}[/red]", file=sys.stderr)
            return 2

        cli_runner = CanaryScannerCLI(args.patterns_file)
        cli_runner.configure_repo_context(args.repository, args.commit, args.branch)

        # Run scan (includes validation if --validate is passed)
        results = await cli_runner.scan_target(
            args.path,
            verbose=args.verbose,
            fail_on=args.fail_on, # Passed for exit code calculation
            validate=args.validate # Pass validate flag
            # Note: Context filtering is handled inside core.py based on ContextAnalyzer
        )

        # --- Output / Reporting ---
        if args.output_json:
            print(json.dumps(results, indent=2))
        else:
            cli_runner.display_console_results(results, ci_mode=args.ci_mode)

        # Dashboard reporting (uses final results which include validation)
        dashboard_success = True
        if args.report_url:
            dashboard_success = await cli_runner.send_to_dashboard(results, args.report_url)
            if not dashboard_success and not args.output_json:
                console.print("⚠️ [yellow]Warning: Failed to submit results to dashboard[/yellow]", file=sys.stderr)

        # Final exit code based on active secrets and fail-on policy
        exit_code = results.get("ci_metadata", {}).get("exit_code", 2) # Default to error if missing

    except KeyboardInterrupt:
        console.print("\n🛑 [yellow]Scan interrupted by user[/yellow]", file=sys.stderr)
        exit_code = 130
    except FileNotFoundError as e:
        console.print(f"❌ [red]Error: {e}[/red]", file=sys.stderr)
        exit_code = 2
    except Exception as e:
        logger.exception("CLI execution failed.")
        console.print(f"❌ [red]An unexpected error occurred in CLI: {e}[/red]", file=sys.stderr)
        exit_code = 2
    finally:
        # Ensure httpx client resources are cleaned up if validation_client was used
        # (httpx clients used via 'async with' usually handle this, but explicit close is safe)
        # await validation_client.close() # Add a close method if needed
        pass

    return exit_code


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    exit_code = loop.run_until_complete(main())
    sys.exit(exit_code)
