import random
import datetime
import ipaddress
import logging
import os
from pathlib import Path

# Configure loguru or standard logging for the script itself (not the generated logs)
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Constants for log generation
TOTAL_LOGS_TARGET = 2500
START_DATE = datetime.datetime.now() - datetime.timedelta(days=30)
OUTPUT_DIR = Path(__file__).parent.parent / "logs"
OUTPUT_FILE = OUTPUT_DIR / "generated_auth.log"

# Define some common users and IP pools
COMMON_USERS = [
    "root",
    "admin",
    "ubuntu",
    "ec2-user",
    "postgres",
    "nginx",
    "jenkins",
    "git",
    "test",
    "user",
]
INTERNAL_IPS = [f"192.168.1.{i}" for i in range(10, 50)]
EXTERNAL_IPS = [str(ipaddress.IPv4Address(random.randint(0, 2**32 - 1))) for _ in range(100)]


def generate_timestamp(start: datetime.datetime, end: datetime.datetime) -> datetime.datetime:
    """Generate a random timestamp between start and end."""
    delta = end - start
    random_second = random.randint(0, int(delta.total_seconds()))
    return start + datetime.timedelta(seconds=random_second)


def format_syslog(
    timestamp: datetime.datetime, host: str, process: str, pid: int, message: str
) -> str:
    """Format a log entry in standard syslog format."""
    # Example: Mar  1 12:34:56 hostname sshd[1234]: message
    ts_str = timestamp.strftime("%b %d %H:%M:%S")
    return f"{ts_str} {host} {process}[{pid}]: {message}"


def generate_normal_login(timestamp: datetime.datetime) -> list[str]:
    """Generate logs for a successful, normal login."""
    user = random.choice(["admin", "ubuntu", "ec2-user"])
    ip = random.choice(INTERNAL_IPS + EXTERNAL_IPS[:10])  # Mostly known IPs
    pid = random.randint(1000, 9999)
    port = random.randint(30000, 60000)

    logs = [
        format_syslog(
            timestamp,
            "server-01",
            "sshd",
            pid,
            f"Accepted publickey for {user} from {ip} port {port} ssh2: RSA SHA256:...",
        ),
        format_syslog(
            timestamp + datetime.timedelta(seconds=1),
            "server-01",
            "sshd",
            pid,
            f"pam_unix(sshd:session): session opened for user {user} by (uid=0)",
        ),
    ]
    return logs


def generate_brute_force(start_time: datetime.datetime) -> list[str]:
    """Generate logs for a brute force attack (many failed login attempts from one IP)."""
    ip = random.choice(EXTERNAL_IPS[10:])
    user = random.choice(["root", "admin"])
    logs = []
    current_time = start_time

    attempts = random.randint(50, 200)
    for _ in range(attempts):
        pid = random.randint(1000, 9999)
        port = random.randint(30000, 60000)
        logs.append(
            format_syslog(
                current_time,
                "server-01",
                "sshd",
                pid,
                f"Failed password for {user} from {ip} port {port} ssh2",
            )
        )
        current_time += datetime.timedelta(seconds=random.randint(1, 4))  # Fast attempts

    return logs


def generate_credential_stuffing(start_time: datetime.datetime) -> list[str]:
    """Generate logs for credential stuffing (many failed logins across different users from one or few IPs)."""
    ip = random.choice(EXTERNAL_IPS[10:])
    logs = []
    current_time = start_time

    attempts = random.randint(30, 100)
    for _ in range(attempts):
        user = random.choice(COMMON_USERS)  # Different user each time
        pid = random.randint(1000, 9999)
        port = random.randint(30000, 60000)
        logs.append(
            format_syslog(
                current_time,
                "server-01",
                "sshd",
                pid,
                f"Failed password for invalid user {user} from {ip} port {port} ssh2"
                if random.random() < 0.3
                else f"Failed password for {user} from {ip} port {port} ssh2",
            )
        )
        current_time += datetime.timedelta(seconds=random.randint(2, 5))

    return logs


def generate_low_and_slow(start_time: datetime.datetime) -> list[str]:
    """Generate logs for a low and slow attack (failed attempts spread out over a long time)."""
    ip = random.choice(EXTERNAL_IPS[10:])
    user = "root"
    logs = []
    current_time = start_time

    attempts = random.randint(10, 30)
    for _ in range(attempts):
        pid = random.randint(1000, 9999)
        port = random.randint(30000, 60000)
        logs.append(
            format_syslog(
                current_time,
                "server-01",
                "sshd",
                pid,
                f"Failed password for {user} from {ip} port {port} ssh2",
            )
        )
        # Wait a long time between attempts (e.g. 10 to 60 minutes)
        current_time += datetime.timedelta(minutes=random.randint(10, 60))

    return logs


def generate_off_hour_access(start_time: datetime.datetime) -> list[str]:
    """Generate a successful login at an unusual time (e.g., 3 AM)."""
    # Force time to be between 1 AM and 4 AM
    off_hour_start = start_time.replace(hour=random.randint(1, 4), minute=random.randint(0, 59))
    user = random.choice(["admin", "ubuntu"])
    ip = random.choice(EXTERNAL_IPS[10:])
    pid = random.randint(1000, 9999)
    port = random.randint(30000, 60000)

    logs = [
        format_syslog(
            off_hour_start,
            "server-01",
            "sshd",
            pid,
            f"Accepted password for {user} from {ip} port {port} ssh2",
        ),
        format_syslog(
            off_hour_start + datetime.timedelta(seconds=1),
            "server-01",
            "sshd",
            pid,
            f"pam_unix(sshd:session): session opened for user {user} by (uid=0)",
        ),
    ]
    return logs


def main():
    """Main function to orchestrate log generation."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    end_date = datetime.datetime.now()
    all_logs = []

    logger.info(f"Generating synthetic SSH logs to {OUTPUT_FILE}...")

    # Generate background noise (normal behavior)
    num_normal = int(TOTAL_LOGS_TARGET * 0.7)  # 70% normal logs
    logger.info(f"Generating ~{num_normal} normal login events...")
    for _ in range(num_normal // 2):  # Each success is 2 log lines
        ts = generate_timestamp(START_DATE, end_date)
        # Ensure 'normal' logins usually happen during business hours (8-18)
        if 8 <= ts.hour <= 18:
            all_logs.extend(generate_normal_login(ts))
        else:
            # Shift back to business hours
            ts = ts.replace(hour=random.randint(8, 18))
            all_logs.extend(generate_normal_login(ts))

    # Generate anomalies (30%)
    logger.info(
        "Generating anomalies (brute force, credential stuffing, low-and-slow, off-hour)..."
    )

    # 1. Brute Force (High volume, short time, single user)
    for _ in range(5):
        ts = generate_timestamp(START_DATE, end_date)
        all_logs.extend(generate_brute_force(ts))

    # 2. Credential Stuffing (High volume, short time, multiple users)
    for _ in range(4):
        ts = generate_timestamp(START_DATE, end_date)
        all_logs.extend(generate_credential_stuffing(ts))

    # 3. Low and Slow (Low volume, long time)
    for _ in range(3):
        ts = generate_timestamp(START_DATE, end_date)
        all_logs.extend(generate_low_and_slow(ts))

    # 4. Off-hour access (Successful login during weird hours)
    for _ in range(10):
        ts = generate_timestamp(START_DATE, end_date)
        all_logs.extend(generate_off_hour_access(ts))

    # Sort logs chronologically based on the timestamp str
    # Since syslog format is 'Mar 01 12:34:56', sorting alphabetically might be slightly off due to month names.
    # We will sort by parsing the date briefly.
    def sort_key(log_line: str):
        date_str = " ".join(log_line.split()[:3])
        try:
            # Assuming current year for sorting purposes
            dt = datetime.datetime.strptime(f"{START_DATE.year} {date_str}", "%Y %b %d %H:%M:%S")
            return dt
        except ValueError:
            return START_DATE

    all_logs.sort(key=sort_key)

    # Write to file
    with open(OUTPUT_FILE, "w") as f:
        for log in all_logs:
            f.write(f"{log}\n")

    logger.info(f"Successfully generated {len(all_logs)} log entries at {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
