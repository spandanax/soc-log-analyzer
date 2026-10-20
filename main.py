
import csv
from analyzer import analyze_logs


with open("sample_logs.csv", "r", newline="") as file:
    logs = list(csv.DictReader(file))

result = analyze_logs(logs)

successful = result["successful_logins"]
failed = result["total_failed_logins"]
attempts = result["failed_attempts"]
suspicious_ips = result["suspicious_ips"]
failed_records = result["failed_records"]

print("\n===== SOC LOG ANALYZER =====")
print(f"Successful logins: {successful}")
print(f"Failed logins: {failed}")

print("\n===== SECURITY ALERTS =====")

if suspicious_ips:
    for ip in sorted(suspicious_ips):
        print(f"ALERT: {ip} had {attempts[ip]} failed login attempts!")
else:
    print("No suspicious repeated logins detected.")

with open("security_report.txt", "w", encoding="utf-8") as report:
    report.write("===== SOC SECURITY REPORT =====\n")
    report.write(f"Successful logins: {successful}\n")
    report.write(f"Failed logins: {failed}\n\n")
    report.write("===== SUSPICIOUS LOGIN ATTEMPTS =====\n")

    if suspicious_ips:
        for ip in sorted(suspicious_ips):
            report.write(
                f"ALERT: {ip} had {attempts[ip]} failed login attempts.\n"
            )

        report.write("\nRelated failed login records:\n")

        for log in failed_records:
            if log["source_ip"].strip() in suspicious_ips:
                report.write(
                    f"{log['timestamp']} | {log['username']} | "
                    f"{log['source_ip']} | {log['status']}\n"
                )
    else:
        report.write("No suspicious repeated logins detected.\n")

print("\nSecurity report saved to security_report.txt")
