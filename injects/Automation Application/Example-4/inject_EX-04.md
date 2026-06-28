Team: Team 10

Inject Name: Technical Inject 1: Web Server Enumeration

Inject ID: TI-01

The screenshot shows an intercepted HTTP POST request to a login page and the successful server response, highlighting captured credentials.

Technical Analysis

The Burp Suite output for http://goodgames.htb (10.129.18.10) revealed the following key observations:

- Cleartext credentials captured in POST body: email 'admin@kdsf.fdk' and password 'admin'
- Successful login indicated by 'HTTP/1.1 200 OK' and 'Set-Cookie: session' in response
- Server version disclosure: Werkzeug/2.0.2 Python/3.9.2

Impact and Recommendations

**Impact:** The capture demonstrates the use of weak administrative credentials ('admin'), allowing an attacker to gain unauthorized access to the application and potentially exploit further internal functionality.

**Recommendation:** Enforce strong password policies to prevent the use of default or weak passwords like 'admin' and ensure communications are encrypted via HTTPS to protect credentials in transit.

Device

http://goodgames.htb (10.129.18.10)

Service

Cleartext credentials captured in POST body: email 'admin@kdsf.fdk' and password 'admin'

Analysis of Vulnerabilities

- Cleartext credentials captured in POST body: email 'admin@kdsf.fdk' and password 'admin'
- Successful login indicated by 'HTTP/1.1 200 OK' and 'Set-Cookie: session' in response
- Server version disclosure: Werkzeug/2.0.2 Python/3.9.2

<picture>

Figure #: Screenshot of Burp Suite output against http://goodgames.htb (10.129.18.10) showing key evidence referenced above.

