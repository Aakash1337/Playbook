Team: Team 10

Inject Name: Technical Inject 1: Web Server Enumeration

Inject ID: TI-01

The screenshot demonstrates the successful exploitation of an SQL injection vulnerability to dump the 'user' table from the 'main' database.

Technical Analysis

The sqlmap output for goodgames.htb revealed the following key observations:

- Database dump of table 'user' revealed administrator credentials.
- Username found: 'admin'
- Email found: 'admin@goodgames.htb'
- Password hash extracted: '2b22337f218b2d82dfc3b6f77e7cb8ec'

Impact and Recommendations

**Impact:** An attacker has successfully exfiltrated sensitive database contents, including administrator credentials, which likely leads to full application or system compromise.

**Recommendation:** Immediately remediate the SQL injection vulnerability by implementing parameterized queries (prepared statements) and rotate all compromised credentials.

Device

goodgames.htb

Service

Database dump of table 'user' revealed administrator credentials.

Analysis of Vulnerabilities

- Database dump of table 'user' revealed administrator credentials.
- Username found: 'admin'
- Email found: 'admin@goodgames.htb'
- Password hash extracted: '2b22337f218b2d82dfc3b6f77e7cb8ec'

<picture>

Figure #: Screenshot of sqlmap output against goodgames.htb showing key evidence referenced above.

