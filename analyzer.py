
from collections import Counter


def find_suspicious_ips(failed_attempts, threshold=5):
    return {
        ip for ip, count in failed_attempts.items()
        if count >= threshold
    }


def analyze_logs(logs):
    failed_attempts = Counter()
    successful_logins = 0
    total_failed_logins = 0
    failed_records = []

    for log in logs:
        ip_address = log["source_ip"].strip()
        status = log["status"].strip().upper()

        if status == "FAILED":
            failed_attempts[ip_address] += 1
            total_failed_logins += 1
            failed_records.append(log)

        elif status == "SUCCESS":
            successful_logins += 1

    suspicious_ips = find_suspicious_ips(failed_attempts)

    return {
        "successful_logins": successful_logins,
        "total_failed_logins": total_failed_logins,
        "failed_attempts": failed_attempts,
        "failed_records": failed_records,
        "suspicious_ips": suspicious_ips,
    }
