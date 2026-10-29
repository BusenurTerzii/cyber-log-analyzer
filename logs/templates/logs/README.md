# Cybersecurity Log Analyzer

A Python and Django-based web application for analyzing security logs, identifying suspicious IP activity, detecting potential brute-force attacks, and managing security alerts.

## Features

- **Security Log Analysis:** Analyze security events and review suspicious activity.
- **Suspicious IP Detection:** Identify IP addresses with repeated failed login attempts.
- **Brute-Force Detection:** Detect multiple failed login attempts within a defined time window.
- **IP Risk Analysis:** Classify IP activity and display risk levels.
- **Security Dashboard:** View event statistics, charts, critical events, and recent activity.
- **Alert Management:** Review security alerts and mark them as reviewed.
- **JSON Report Export:** Export security analysis results as a JSON report.
- **Log Import:** Import log data and handle duplicate entries.

## Technologies

- Python
- Django
- SQLite
- HTML
- CSS
- JavaScript
- Chart.js
- Git and GitHub

## Project Structure

```text
cyber_log_analyzer/
├── config/
├── logs/
│   ├── analysis.py
│   ├── risk_analysis.py
│   ├── log_reader.py
│   ├── models.py
│   ├── views.py
│   ├── urls.py
│   └── templates/
├── manage.py
├── security_report.json
└── README.md
```

*Note: The structure above is illustrative. Adjust it to match the actual files in your repository before publishing.*

## Installation

### 1. Clone the repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd cyber_log_analyzer
```

### 2. Create and activate a virtual environment

Windows PowerShell:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 3. Install dependencies

Install the project's dependencies from `requirements.txt` if the file is included:

```bash
pip install -r requirements.txt
```

### 4. Apply database migrations

```bash
python manage.py migrate
```

### 5. Start the development server

```bash
python manage.py runserver
```

Open `http://127.0.0.1:8000/` in your browser. If your project uses a custom port, use that port instead.

## Testing

Run the application tests with:

```bash
python manage.py test logs
```

The current test suite has passed 17 tests in the development environment.

## Security Notice

This project is intended for educational and development purposes. Risk classifications and brute-force detections are indicators for further investigation, not definitive proof of an attack.

Do not publish real credentials, secret keys, sensitive log data, or personal information in the repository.

## Future Improvements

- More advanced detection rules
- Additional log formats
- Improved reporting and visualizations
- Automated testing and deployment

## Author

Developed as a Python and Django cybersecurity learning project.
