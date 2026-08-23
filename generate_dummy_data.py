#!/usr/bin/env python3
"""
Dummy Authentication Log Generator for SSH Log Sentinel Testing

This script generates realistic fake authentication log data that mimics
the format of Linux auth.log files. It creates a mixture of legitimate
traffic and malicious brute-force attack patterns for testing purposes.

Author: Senior Cybersecurity Engineer
License: MIT
Python Version: 3.8+
"""

import argparse
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Tuple


class DummyLogGenerator:
    """
    Generates realistic fake SSH authentication logs for testing.
    
    This class creates log entries that simulate both normal SSH usage
    and brute-force attack patterns, allowing for comprehensive testing
    of the SSH Log Sentinel tool.
    """
    
    # Common legitimate usernames
    LEGITIMATE_USERS = [
        'admin', 'john', 'sarah', 'developer', 'devops', 'sysadmin',
        'webmaster', 'backup', 'deploy', 'jenkins', 'ubuntu', 'centos'
    ]
    
    # Common usernames targeted by attackers
    ATTACK_USERNAMES = [
        'root', 'admin', 'test', 'user', 'oracle', 'postgres', 'mysql',
        'administrator', 'guest', 'ftpuser', 'tomcat', 'nginx', 'apache',
        'hadoop', 'jenkins', 'git', 'minecraft', 'teamspeak', 'ubuntu',
        'pi', 'vagrant', 'ansible', 'docker', 'kubernetes', 'redis'
    ]
    
    # Legitimate IP ranges (simulating internal network and known hosts)
    LEGITIMATE_IPS = [
        '192.168.1.', '10.0.0.', '172.16.0.', '203.0.113.'
    ]
    
    # Malicious IP addresses (specific IPs for brute-force attacks)
    MALICIOUS_IPS = [
        '185.220.101.45',  # High-volume attacker
        '103.99.0.122',     # Medium-volume attacker
        '45.155.205.33',    # Critical-level attacker
        '198.98.51.189',    # Another high-volume source
        '91.240.118.168',   # Persistent attacker
        '139.59.47.201',    # Medium threat
        '159.65.88.43',     # Low-medium attacker
    ]
    
    # SSH log message templates
    LOG_TEMPLATES = {
        'failed_password': (
            "{timestamp} {hostname} sshd[{pid}]: Failed password for "
            "{username} from {ip} port {port} ssh2"
        ),
        'failed_invalid_user': (
            "{timestamp} {hostname} sshd[{pid}]: Failed password for "
            "invalid user {username} from {ip} port {port} ssh2"
        ),
        'invalid_user': (
            "{timestamp} {hostname} sshd[{pid}]: Invalid user {username} "
            "from {ip} port {port}"
        ),
        'auth_failure': (
            "{timestamp} {hostname} sshd[{pid}]: PAM {count} more "
            "authentication failure; logname= uid=0 euid=0 tty=ssh "
            "ruser= rhost={ip}  user={username}"
        ),
        'connection_closed': (
            "{timestamp} {hostname} sshd[{pid}]: Connection closed by "
            "authenticating user {username} {ip} port {port} [preauth]"
        ),
        'accepted_password': (
            "{timestamp} {hostname} sshd[{pid}]: Accepted password for "
            "{username} from {ip} port {port} ssh2"
        ),
        'session_opened': (
            "{timestamp} {hostname} sshd[{pid}]: pam_unix(sshd:session): "
            "session opened for user {username} by (uid=0)"
        ),
        'session_closed': (
            "{timestamp} {hostname} sshd[{pid}]: pam_unix(sshd:session): "
            "session closed for user {username}"
        ),
        'disconnected': (
            "{timestamp} {hostname} sshd[{pid}]: Received disconnect from "
            "{ip} port {port}:11: Bye Bye [preauth]"
        )
    }
    
    def __init__(
        self,
        total_lines: int = 1000,
        attack_ratio: float = 0.7,
        hostname: str = "sentinel-test"
    ):
        """
        Initialize the dummy log generator.
        
        Args:
            total_lines: Total number of log lines to generate
            attack_ratio: Ratio of attack lines to legitimate traffic (0.0-1.0)
            hostname: Hostname to use in log entries
        """
        self.total_lines = total_lines
        self.attack_ratio = attack_ratio
        self.hostname = hostname
        self.base_time = datetime.now() - timedelta(days=7)
    
    def _generate_timestamp(self, offset_minutes: int = 0) -> str:
        """
        Generate a timestamp in auth.log format.
        
        Args:
            offset_minutes: Minutes to offset from base time
            
        Returns:
            Formatted timestamp string (e.g., "Nov 22 14:30:45")
        """
        timestamp = self.base_time + timedelta(minutes=offset_minutes)
        return timestamp.strftime("%b %d %H:%M:%S")
    
    def _generate_legitimate_ip(self) -> str:
        """
        Generate a legitimate IP address.
        
        Returns:
            IP address string
        """
        prefix = random.choice(self.LEGITIMATE_IPS)
        suffix = random.randint(1, 254)
        return f"{prefix}{suffix}"
    
    def _generate_attack_ip(self) -> str:
        """
        Generate a malicious IP address.
        
        Returns:
            IP address string from the malicious IP pool
        """
        return random.choice(self.MALICIOUS_IPS)
    
    def _generate_legitimate_entry(self, time_offset: int) -> str:
        """
        Generate a legitimate log entry (successful login or normal activity).
        
        Args:
            time_offset: Time offset in minutes
            
        Returns:
            Formatted log entry string
        """
        template_choice = random.choice([
            'accepted_password', 'session_opened', 'session_closed'
        ])
        
        return self.LOG_TEMPLATES[template_choice].format(
            timestamp=self._generate_timestamp(time_offset),
            hostname=self.hostname,
            pid=random.randint(1000, 99999),
            username=random.choice(self.LEGITIMATE_USERS),
            ip=self._generate_legitimate_ip(),
            port=random.randint(40000, 65535)
        )
    
    def _generate_attack_entry(self, time_offset: int, ip: str) -> str:
        """
        Generate a malicious log entry (failed login attempt).
        
        Args:
            time_offset: Time offset in minutes
            ip: IP address to use
            
        Returns:
            Formatted log entry string
        """
        template_choice = random.choice([
            'failed_password', 'failed_invalid_user', 'invalid_user',
            'auth_failure', 'connection_closed'
        ])
        
        username = random.choice(self.ATTACK_USERNAMES)
        
        template_data = {
            'timestamp': self._generate_timestamp(time_offset),
            'hostname': self.hostname,
            'pid': random.randint(1000, 99999),
            'username': username,
            'ip': ip,
            'port': random.randint(40000, 65535),
            'count': random.randint(1, 3)
        }
        
        return self.LOG_TEMPLATES[template_choice].format(**template_data)
    
    def generate_log_data(self) -> List[str]:
        """
        Generate the complete set of log entries.
        
        Returns:
            List of log entry strings
        """
        log_entries: List[str] = []
        
        # Calculate how many attack lines to generate
        attack_lines = int(self.total_lines * self.attack_ratio)
        legitimate_lines = self.total_lines - attack_lines
        
        # Generate attack patterns for each malicious IP
        # Distribute attacks across different IPs with varying intensities
        attack_distribution = {
            self.MALICIOUS_IPS[0]: int(attack_lines * 0.30),  # 30% - Critical
            self.MALICIOUS_IPS[1]: int(attack_lines * 0.20),  # 20% - High
            self.MALICIOUS_IPS[2]: int(attack_lines * 0.25),  # 25% - Critical
            self.MALICIOUS_IPS[3]: int(attack_lines * 0.15),  # 15% - High
            self.MALICIOUS_IPS[4]: int(attack_lines * 0.05),  # 5% - Medium
            self.MALICIOUS_IPS[5]: int(attack_lines * 0.03),  # 3% - Medium
            self.MALICIOUS_IPS[6]: int(attack_lines * 0.02),  # 2% - Low
        }
        
        # Generate attack entries
        time_offset = 0
        for ip, count in attack_distribution.items():
            for _ in range(count):
                entry = self._generate_attack_entry(time_offset, ip)
                log_entries.append(entry)
                time_offset += random.randint(0, 5)  # Attacks come in bursts
        
        # Generate legitimate entries
        for _ in range(legitimate_lines):
            entry = self._generate_legitimate_entry(time_offset)
            log_entries.append(entry)
            time_offset += random.randint(5, 30)  # Normal activity is spread out
        
        # Shuffle to mix legitimate and malicious entries realistically
        random.shuffle(log_entries)
        
        return log_entries
    
    def save_to_file(self, output_path: str) -> None:
        """
        Generate and save log data to a file.
        
        Args:
            output_path: Path where the log file should be saved
        """
        log_entries = self.generate_log_data()
        
        output_file = Path(output_path)
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                for entry in log_entries:
                    f.write(entry + '\n')
            
            print(f"✓ Generated {len(log_entries)} log entries")
            print(f"✓ Saved to: {output_file.absolute()}")
            print(f"\nLog Statistics:")
            print(f"  - Total lines: {self.total_lines}")
            print(f"  - Attack lines: ~{int(self.total_lines * self.attack_ratio)}")
            print(f"  - Legitimate lines: ~{self.total_lines - int(self.total_lines * self.attack_ratio)}")
            print(f"  - Malicious IPs: {len(self.MALICIOUS_IPS)}")
            print(f"\nMalicious IPs in dataset:")
            for ip in self.MALICIOUS_IPS:
                print(f"  - {ip}")
            
        except PermissionError:
            print(f"❌ Error: Permission denied writing to {output_path}")
            raise
        except Exception as e:
            print(f"❌ Error generating log file: {str(e)}")
            raise


def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments.
    
    Returns:
        Parsed arguments namespace
    """
    parser = argparse.ArgumentParser(
        description='Generate dummy SSH authentication log data for testing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --output auth.log --lines 1000
  %(prog)s --output test_auth.log --lines 5000 --attack-ratio 0.8
  %(prog)s --output /var/log/test_auth.log --lines 2000 --hostname myserver

This will generate a mix of legitimate SSH traffic and brute-force attacks
from specific malicious IPs, allowing you to test the SSH Log Sentinel tool.
        """
    )
    
    parser.add_argument(
        '--output',
        type=str,
        default='auth.log',
        help='Output file path for the generated log (default: auth.log)'
    )
    
    parser.add_argument(
        '--lines',
        type=int,
        default=1000,
        help='Total number of log lines to generate (default: 1000)'
    )
    
    parser.add_argument(
        '--attack-ratio',
        type=float,
        default=0.7,
        help='Ratio of attack lines to total (0.0-1.0, default: 0.7)'
    )
    
    parser.add_argument(
        '--hostname',
        type=str,
        default='sentinel-test',
        help='Hostname to use in log entries (default: sentinel-test)'
    )
    
    return parser.parse_args()


def main() -> int:
    """
    Main entry point for the dummy log generator.
    
    Returns:
        Exit code (0 for success, 1 for error)
    """
    try:
        args = parse_arguments()
        
        # Validate attack ratio
        if not 0.0 <= args.attack_ratio <= 1.0:
            print("❌ Error: --attack-ratio must be between 0.0 and 1.0")
            return 1
        
        # Validate line count
        if args.lines < 10:
            print("❌ Error: --lines must be at least 10")
            return 1
        
        print("SSH Log Sentinel - Dummy Log Generator")
        print("=" * 50)
        print(f"Generating {args.lines} log entries...")
        print()
        
        # Generate log data
        generator = DummyLogGenerator(
            total_lines=args.lines,
            attack_ratio=args.attack_ratio,
            hostname=args.hostname
        )
        
        generator.save_to_file(args.output)
        
        print()
        print("=" * 50)
        print("✓ Log generation complete!")
        print()
        print("Next steps:")
        print(f"  python log_sentinel.py --file {args.output} --threshold 5")
        
        return 0
        
    except KeyboardInterrupt:
        print("\n\n⚠ Generation interrupted by user")
        return 1
    except Exception as e:
        print(f"\n❌ Unexpected error: {str(e)}")
        return 1


if __name__ == '__main__':
    sys.exit(main())
