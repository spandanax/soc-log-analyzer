# SOC Log Analyzer 🔐

A beginner-friendly cybersecurity project built with Python to analyze login logs, detect repeated failed login attempts, and generate a security report.

## 🚀 Features

- Reads login records from a CSV file.
- Counts successful and failed login attempts.
- Tracks failed attempts by source IP address.
- Detects suspicious IP addresses with five or more failed login attempts.
- Generates a security report in `security_report.txt`.
- Includes automated unit tests to verify detection logic.

## 🛠️ Technologies Used

- Python 3
- CSV file processing
- `collections.Counter`
- Python `unittest`

## 📁 Project Structure

```text
soc-log-analyzer/
├── main.py
├── analyzer.py
├── sample_logs.csv
├── test_analyzer.py
├── README.md
└── security_report.txt
```

## ⚙️ How to Run

**1. Clone the repository**

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
```

**2. Open the project folder**

```bash
cd soc-log-analyzer
```

**3. Run the analyzer**

```bash
python main.py
```

**4. Run the tests**

```bash
python -m unittest -v test_analyzer.py
```

## 🧪 Example Detection

The analyzer checks login records and flags an IP address when it has five or more failed login attempts.

Example alert:

```text
ALERT: 198.51.100.20 had 5 failed login attempts!
```

## 🎯 Learning Objectives

- Understand basic security log analysis.
- Identify repeated authentication failures.
- Practice Python data processing and testing.
- Learn how simple detection rules support Security Operations Center (SOC) workflows.

## ⚠️ Disclaimer

This is an educational project that uses fictional sample log data. Detection results indicate suspicious activity for investigation; they do not prove that an attack occurred.
