🚀 Installation & Running the App
1️⃣ Clone the Repository
git clone https://github.com/SirAppSec/vuln-node.js-express.js-app.git
cd vuln-node.js-express.js-app

2️⃣ Install Dependencies
npm install

3️⃣ Run the Application
npm run dev

4️⃣ Access the App
http://localhost:5000

🕷 Running OWASP ZAP (DAST)
🔹 Automated Scan (GUI)

Open OWASP ZAP

Enter target URL:

http://localhost:5000


Use:

Spider

Active Scan

Review alerts under:

SQL Injection

XSS

Broken Access Control

RCE

SSRF

🔹 Manual Testing (Optional)

Manual tests were performed using Postman and browser requests to validate:

SQL Injection

XSS

Authentication & Authorization flaws

Remote Code Execution

Sensitive data exposure

🔍 Running Semgrep (SAST)
1️⃣ Install Semgrep
pip install semgrep


Verify installation:

semgrep --version

2️⃣ Run Semgrep Built-in Rules
semgrep \
  --config "p/javascript" \
  --config "p/nodejs" \
  --error \
  --json > sast-output.json


This scans the project using official Semgrep rules for:

JavaScript

Node.js

Express security issues

3️⃣ Run Semgrep with Custom Rules

Custom rules are located in the semgrep-rules/ directory.

semgrep \
  --config semgrep-rules/ \
  src/

🧪 Custom Semgrep Rules

The following custom rules were written to detect exploited vulnerabilities:

Rule File	Detects
node-rce-command-injection.yaml	OS command injection (exec / execSync)
express-sequelize-injection.yaml	Raw SQL queries via Sequelize
express-excessive-user-data-exposure.yaml	PII exposure via ORM includes

These rules directly map DAST findings → vulnerable code patterns.

🔁 Re-Testing
✔ Semgrep

Fixed vulnerabilities are no longer flagged

Remaining findings represent defense-in-depth warnings

✔ OWASP ZAP

SQL Injection payloads no longer work

RCE endpoint no longer executes commands

Sensitive user data is no longer exposed

📂 Project Structure
.
├── src/
│   ├── router/
│   │   └── routes/
├── semgrep-rules/
│   ├── node-rce-command-injection.yaml
│   ├── express-sequelize-injection.yaml
│   └── express-excessive-user-data-exposure.yaml
├── README.md
└── package.json

📚 Tools Used

Node.js / Express

OWASP ZAP

Semgrep

Postman

⚠️ Disclaimer

This project is for educational purposes only.
All testing was performed on a deliberately vulnerable application in a controlled environment.
