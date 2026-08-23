#!/usr/bin/env python3
"""
SSH Log Sentinel - Production-Grade SSH Brute-Force Attack Detection Tool

This module provides a robust, enterprise-ready solution for detecting SSH
brute-force attacks by analyzing Linux authentication logs. It implements
OOP principles with comprehensive error handling and flexible output formats.

Author: Senior Cybersecurity Engineer
License: MIT
Python Version: 3.8+
"""

import argparse
import csv
import json
import logging
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)


@dataclass
class FailedLoginAttempt:
    """Data class representing a failed SSH login attempt."""
    
    timestamp: str
    ip_address: str
    username: Optional[str] = None
    port: Optional[int] = None
    log_line: str = ""


@dataclass
class ThreatReport:
    """Data class representing a threat analysis report for an IP address."""
    
    ip_address: str
    failed_attempts: int
    usernames_targeted: List[str] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    threat_level: str = "LOW"
    
    def calculate_threat_level(self) -> None:
        """Calculate threat level based on failed attempts count."""
        if self.failed_attempts >= 100:
            self.threat_level = "CRITICAL"
        elif self.failed_attempts >= 50:
            self.threat_level = "HIGH"
        elif self.failed_attempts >= 20:
            self.threat_level = "MEDIUM"
        else:
            self.threat_level = "LOW"


class LogParser:
    """
    Parses SSH authentication logs to extract failed login attempts.
    
    This class handles the parsing of Linux authentication logs (typically
    /var/log/auth.log or /var/log/secure) using regex patterns to identify
    failed SSH authentication attempts.
    """
    
    # Regex patterns for different log formats
    FAILED_PASSWORD_PATTERN = re.compile(
        r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*?'
        r'Failed password for (?:invalid user )?(?P<username>\S+) from '
        r'(?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)'
    )
    
    FAILED_AUTH_PATTERN = re.compile(
        r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*?'
        r'authentication failure.*?rhost=(?P<ip>\d+\.\d+\.\d+\.\d+)'
        r'(?:.*?user=(?P<username>\S+))?'
    )
    
    INVALID_USER_PATTERN = re.compile(
        r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*?'
        r'Invalid user (?P<username>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)'
    )
    
    CONNECTION_CLOSED_PATTERN = re.compile(
        r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*?'
        r'Connection closed by (?:authenticating user \S+ )?(?P<ip>\d+\.\d+\.\d+\.\d+)'
        r'.*?preauth'
    )
    
    # Pre-computed tuple of (pattern, quick_filter_string) for efficient matching.
    # Each quick_filter_string is a substring that MUST appear in any line matching
    # the corresponding regex pattern. This allows fast O(n) string containment
    # checks to skip expensive regex matching on non-matching lines.
    PATTERNS_WITH_FILTERS: Tuple[Tuple[re.Pattern, str], ...] = (
        (FAILED_PASSWORD_PATTERN, 'Failed password'),
        (FAILED_AUTH_PATTERN, 'authentication failure'),
        (INVALID_USER_PATTERN, 'Invalid user'),
        (CONNECTION_CLOSED_PATTERN, 'preauth'),
    )
    
    def __init__(self, log_file_path: str):
        """
        Initialize the LogParser with a log file path.
        
        Args:
            log_file_path: Path to the authentication log file
            
        Raises:
            FileNotFoundError: If the log file doesn't exist
            PermissionError: If the log file cannot be read
        """
        self.log_file_path = Path(log_file_path)
        self._validate_file()
        logger.info(f"Initialized LogParser for file: {self.log_file_path}")
    
    def _validate_file(self) -> None:
        """
        Validate that the log file exists and is readable.
        
        Raises:
            FileNotFoundError: If file doesn't exist or path is not a file
            PermissionError: If file is not readable
        """
        if not self.log_file_path.exists():
            error_msg = f"Log file not found: {self.log_file_path}"
            logger.error(error_msg)
            raise FileNotFoundError(error_msg)
        
        if not self.log_file_path.is_file():
            error_msg = f"Path is not a file: {self.log_file_path}"
            logger.error(error_msg)
            raise FileNotFoundError(error_msg)
        
        if not self.log_file_path.stat().st_size > 0:
            logger.warning(f"Log file is empty: {self.log_file_path}")
    
    def parse_log_file(self) -> List[FailedLoginAttempt]:
        """
        Parse the log file and extract all failed login attempts.
        
        Returns:
            List of FailedLoginAttempt objects
            
        Raises:
            PermissionError: If unable to read the file
            Exception: For other parsing errors
        """
        failed_attempts: List[FailedLoginAttempt] = []
        
        try:
            with open(self.log_file_path, 'r', encoding='utf-8', errors='ignore') as file:
                line_count = 0
                for line in file:
                    line_count += 1
                    attempt = self._parse_line(line)
                    if attempt:
                        failed_attempts.append(attempt)
                
                logger.info(
                    f"Parsed {line_count} lines, found {len(failed_attempts)} "
                    f"failed login attempts"
                )
                
        except PermissionError as e:
            error_msg = f"Permission denied reading file: {self.log_file_path}"
            logger.error(error_msg)
            raise PermissionError(error_msg) from e
        except Exception as e:
            error_msg = f"Error parsing log file: {str(e)}"
            logger.error(error_msg)
            raise
        
        return failed_attempts
    
    def _parse_line(self, line: str) -> Optional[FailedLoginAttempt]:
        """
        Parse a single log line to extract failed login information.
        
        Uses quick string containment checks before expensive regex operations
        to improve performance.
        
        Args:
            line: A single line from the log file
            
        Returns:
            FailedLoginAttempt object if the line indicates a failed attempt,
            None otherwise
        """
        # Try each pattern with quick string filter check first
        for pattern, quick_filter in self.PATTERNS_WITH_FILTERS:
            # Fast string containment check before expensive regex
            if quick_filter not in line:
                continue
            match = pattern.search(line)
            if match:
                # Cache groupdict to avoid calling it twice
                groups = match.groupdict()
                port_str = groups.get('port')
                return FailedLoginAttempt(
                    timestamp=groups['timestamp'],
                    ip_address=groups['ip'],
                    username=groups.get('username'),
                    port=int(port_str) if port_str else None,
                    log_line=line.strip()
                )
        
        return None


class ThreatAnalyzer:
    """
    Analyzes failed login attempts to identify potential brute-force attacks.
    
    This class aggregates failed login attempts by IP address and identifies
    those exceeding a specified threshold, indicating potential attack patterns.
    """
    
    def __init__(self, threshold: int = 5):
        """
        Initialize the ThreatAnalyzer with a detection threshold.
        
        Args:
            threshold: Minimum number of failed attempts to flag an IP as suspicious
        """
        self.threshold = threshold
        self.ip_attempts: Dict[str, List[FailedLoginAttempt]] = defaultdict(list)
        logger.info(f"Initialized ThreatAnalyzer with threshold: {threshold}")
    
    def analyze_attempts(
        self,
        failed_attempts: List[FailedLoginAttempt]
    ) -> List[ThreatReport]:
        """
        Analyze failed login attempts and generate threat reports.
        
        Args:
            failed_attempts: List of FailedLoginAttempt objects
            
        Returns:
            List of ThreatReport objects for IPs exceeding the threshold
        """
        # Group attempts by IP address
        for attempt in failed_attempts:
            self.ip_attempts[attempt.ip_address].append(attempt)
        
        logger.info(
            f"Analyzing {len(failed_attempts)} failed attempts from "
            f"{len(self.ip_attempts)} unique IPs"
        )
        
        # Generate threat reports for IPs exceeding threshold
        threat_reports: List[ThreatReport] = []
        
        for ip_address, attempts in self.ip_attempts.items():
            attempt_count = len(attempts)
            
            if attempt_count >= self.threshold:
                report = self._generate_threat_report(ip_address, attempts)
                threat_reports.append(report)
        
        # Sort by failed attempts (descending)
        threat_reports.sort(key=lambda x: x.failed_attempts, reverse=True)
        
        logger.info(
            f"Identified {len(threat_reports)} IPs exceeding threshold of "
            f"{self.threshold} failed attempts"
        )
        
        return threat_reports
    
    def _generate_threat_report(
        self,
        ip_address: str,
        attempts: List[FailedLoginAttempt]
    ) -> ThreatReport:
        """
        Generate a detailed threat report for a specific IP address.
        
        Args:
            ip_address: The IP address to analyze
            attempts: List of failed attempts from this IP
            
        Returns:
            ThreatReport object with analysis results
        """
        # Extract unique usernames
        usernames = list(set(
            attempt.username for attempt in attempts
            if attempt.username
        ))
        
        # Get first and last seen timestamps
        first_seen = attempts[0].timestamp if attempts else ""
        last_seen = attempts[-1].timestamp if attempts else ""
        
        report = ThreatReport(
            ip_address=ip_address,
            failed_attempts=len(attempts),
            usernames_targeted=usernames,
            first_seen=first_seen,
            last_seen=last_seen
        )
        
        report.calculate_threat_level()
        
        return report
    
    def get_statistics(self) -> Dict[str, int]:
        """
        Get overall statistics about the analysis.
        
        Returns:
            Dictionary containing analysis statistics
        """
        total_attempts = sum(len(attempts) for attempts in self.ip_attempts.values())
        flagged_ips = sum(
            1 for attempts in self.ip_attempts.values()
            if len(attempts) >= self.threshold
        )
        
        return {
            'total_failed_attempts': total_attempts,
            'unique_ips': len(self.ip_attempts),
            'flagged_ips': flagged_ips,
            'threshold': self.threshold
        }


class ReportGenerator:
    """
    Generates formatted reports from threat analysis results.
    
    This class handles the presentation of threat analysis results in various
    formats including console output, CSV, and JSON.
    """
    
    def __init__(self):
        """Initialize the ReportGenerator."""
        logger.info("Initialized ReportGenerator")
    
    def print_console_report(
        self,
        threat_reports: List[ThreatReport],
        statistics: Dict[str, int]
    ) -> None:
        """
        Print a formatted threat report to the console.
        
        Args:
            threat_reports: List of ThreatReport objects
            statistics: Overall statistics dictionary
        """
        print("\n" + "="*80)
        print("SSH LOG SENTINEL - THREAT ANALYSIS REPORT".center(80))
        print("="*80)
        print(f"\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        print("\n" + "-"*80)
        print("SUMMARY STATISTICS")
        print("-"*80)
        print(f"Total Failed Attempts: {statistics['total_failed_attempts']}")
        print(f"Unique Source IPs: {statistics['unique_ips']}")
        print(f"Flagged IPs (≥{statistics['threshold']} attempts): {statistics['flagged_ips']}")
        
        if not threat_reports:
            print("\n✓ No threats detected! All IPs below threshold.")
            print("="*80 + "\n")
            return
        
        print("\n" + "-"*80)
        print("DETECTED THREATS (Sorted by Severity)")
        print("-"*80)
        
        # Table header
        print(f"\n{'IP Address':<18} {'Attempts':<10} {'Threat':<10} {'Usernames':<20} {'Last Seen':<20}")
        print("-"*80)
        
        # Table rows
        for report in threat_reports:
            usernames_str = ', '.join(report.usernames_targeted[:3])
            if len(report.usernames_targeted) > 3:
                usernames_str += f" (+{len(report.usernames_targeted)-3} more)"
            
            # Truncate if too long
            if len(usernames_str) > 18:
                usernames_str = usernames_str[:15] + "..."
            
            print(
                f"{report.ip_address:<18} "
                f"{report.failed_attempts:<10} "
                f"{report.threat_level:<10} "
                f"{usernames_str:<20} "
                f"{report.last_seen:<20}"
            )
        
        print("\n" + "="*80)
        print(f"⚠ WARNING: {len(threat_reports)} potential brute-force sources detected!")
        print("="*80 + "\n")
    
    def export_to_csv(
        self,
        threat_reports: List[ThreatReport],
        output_path: str
    ) -> None:
        """
        Export threat reports to a CSV file.
        
        Args:
            threat_reports: List of ThreatReport objects
            output_path: Path to the output CSV file
            
        Raises:
            PermissionError: If unable to write to the output file
        """
        try:
            output_file = Path(output_path)
            
            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = [
                    'ip_address',
                    'failed_attempts',
                    'threat_level',
                    'usernames_targeted',
                    'first_seen',
                    'last_seen'
                ]
                
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for report in threat_reports:
                    writer.writerow({
                        'ip_address': report.ip_address,
                        'failed_attempts': report.failed_attempts,
                        'threat_level': report.threat_level,
                        'usernames_targeted': ', '.join(report.usernames_targeted),
                        'first_seen': report.first_seen,
                        'last_seen': report.last_seen
                    })
            
            logger.info(f"CSV report exported to: {output_file}")
            print(f"\n✓ CSV report saved to: {output_file}")
            
        except PermissionError as e:
            error_msg = f"Permission denied writing to: {output_path}"
            logger.error(error_msg)
            raise PermissionError(error_msg) from e
        except Exception as e:
            error_msg = f"Error exporting CSV: {str(e)}"
            logger.error(error_msg)
            raise
    
    def export_to_json(
        self,
        threat_reports: List[ThreatReport],
        statistics: Dict[str, int],
        output_path: str
    ) -> None:
        """
        Export threat reports to a JSON file.
        
        Args:
            threat_reports: List of ThreatReport objects
            statistics: Overall statistics dictionary
            output_path: Path to the output JSON file
            
        Raises:
            PermissionError: If unable to write to the output file
        """
        try:
            output_file = Path(output_path)
            
            # Prepare data structure
            report_data = {
                'metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'tool': 'SSH Log Sentinel',
                    'version': '1.0.0'
                },
                'statistics': statistics,
                'threats': [
                    {
                        'ip_address': report.ip_address,
                        'failed_attempts': report.failed_attempts,
                        'threat_level': report.threat_level,
                        'usernames_targeted': report.usernames_targeted,
                        'first_seen': report.first_seen,
                        'last_seen': report.last_seen
                    }
                    for report in threat_reports
                ]
            }
            
            with open(output_file, 'w', encoding='utf-8') as jsonfile:
                json.dump(report_data, jsonfile, indent=2)
            
            logger.info(f"JSON report exported to: {output_file}")
            print(f"\n✓ JSON report saved to: {output_file}")
            
        except PermissionError as e:
            error_msg = f"Permission denied writing to: {output_path}"
            logger.error(error_msg)
            raise PermissionError(error_msg) from e
        except Exception as e:
            error_msg = f"Error exporting JSON: {str(e)}"
            logger.error(error_msg)
            raise


class SSHLogSentinel:
    """
    Main application class coordinating log analysis workflow.
    
    This class orchestrates the entire process of parsing logs, analyzing
    threats, and generating reports.
    """
    
    def __init__(self, log_file: str, threshold: int):
        """
        Initialize the SSH Log Sentinel application.
        
        Args:
            log_file: Path to the authentication log file
            threshold: Minimum failed attempts to flag an IP
        """
        self.parser = LogParser(log_file)
        self.analyzer = ThreatAnalyzer(threshold)
        self.reporter = ReportGenerator()
        logger.info("SSH Log Sentinel initialized successfully")
    
    def run_analysis(self) -> Tuple[List[ThreatReport], Dict[str, int]]:
        """
        Execute the complete threat analysis workflow.
        
        Returns:
            Tuple of (threat_reports, statistics)
            
        Raises:
            Exception: If any step of the analysis fails
        """
        try:
            # Step 1: Parse log file
            logger.info("Starting log analysis...")
            failed_attempts = self.parser.parse_log_file()
            
            # Step 2: Analyze threats
            threat_reports = self.analyzer.analyze_attempts(failed_attempts)
            
            # Step 3: Get statistics
            statistics = self.analyzer.get_statistics()
            
            logger.info("Analysis completed successfully")
            return threat_reports, statistics
            
        except Exception as e:
            logger.error(f"Analysis failed: {str(e)}")
            raise


def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments.
    
    Returns:
        Parsed arguments namespace
    """
    parser = argparse.ArgumentParser(
        description='SSH Log Sentinel - Detect SSH brute-force attacks from authentication logs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --file /var/log/auth.log --threshold 10
  %(prog)s --file auth.log --threshold 5 --output csv --output-file threats.csv
  %(prog)s --file auth.log --threshold 20 --output json --output-file report.json

For more information, visit: https://github.com/Kirat0201/SSH-Log-Analyzer
        """
    )
    
    parser.add_argument(
        '--file',
        type=str,
        required=True,
        help='Path to the authentication log file (e.g., /var/log/auth.log)'
    )
    
    parser.add_argument(
        '--threshold',
        type=int,
        default=5,
        help='Minimum failed login attempts to flag an IP as suspicious (default: 5)'
    )
    
    parser.add_argument(
        '--output',
        type=str,
        choices=['csv', 'json', 'both'],
        help='Export format: csv, json, or both'
    )
    
    parser.add_argument(
        '--output-file',
        type=str,
        help='Output file path (for CSV or JSON export). If --output is "both", this becomes the base name.'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='SSH Log Sentinel v1.0.0'
    )
    
    return parser.parse_args()


def main() -> int:
    """
    Main entry point for the SSH Log Sentinel application.
    
    Returns:
        Exit code (0 for success, 1 for error)
    """
    try:
        # Parse command-line arguments
        args = parse_arguments()
        
        # Initialize and run analysis
        sentinel = SSHLogSentinel(args.file, args.threshold)
        threat_reports, statistics = sentinel.run_analysis()
        
        # Always print console report
        sentinel.reporter.print_console_report(threat_reports, statistics)
        
        # Export to requested format(s) - even if empty for consistency
        if args.output:
            if args.output in ['csv', 'both']:
                csv_file = args.output_file if args.output == 'csv' else f"{args.output_file or 'threats'}.csv"
                sentinel.reporter.export_to_csv(threat_reports, csv_file)
            
            if args.output in ['json', 'both']:
                json_file = args.output_file if args.output == 'json' else f"{args.output_file or 'threats'}.json"
                sentinel.reporter.export_to_json(threat_reports, statistics, json_file)
        
        return 0
        
    except FileNotFoundError as e:
        logger.error(f"File not found: {str(e)}")
        print(f"\n❌ Error: {str(e)}", file=sys.stderr)
        return 1
    except PermissionError as e:
        logger.error(f"Permission error: {str(e)}")
        print(f"\n❌ Error: {str(e)}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        logger.info("Analysis interrupted by user")
        print("\n\n⚠ Analysis interrupted by user")
        return 1
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        print(f"\n❌ Unexpected error: {str(e)}", file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
