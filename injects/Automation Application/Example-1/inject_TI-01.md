Team: Team 10

Inject Name: Technical Inject 1: Web Server Enumeration

Inject ID: TI-01

An Nmap scan result showing open ports and service details for a target host.

Technical Analysis

The Nmap output for goodgames.htb revealed the following key observations:

- Port 80/tcp is open running HTTP.
- Service detected as Apache httpd 2.4.48.
- The http-server-header reveals the backend is likely Python/3.9.2 using Werkzeug/2.0.2.
- Web page title: 'GoodGames | Community and Store'.
- Internal hostname identified as 'goodgames.htb'.

Impact and Recommendations

**Impact:** The open web service provides a potential attack vector into the system, and version disclosure allows attackers to research specific vulnerabilities for the running software stack.

**Recommendation:** Add 'goodgames.htb' to the local hosts file to access the site properly and perform thorough web application testing (directory enumeration, vulnerability scanning).

Device

goodgames.htb

Service

Port 80/tcp is open running HTTP.

Analysis of Vulnerabilities

- Port 80/tcp is open running HTTP.
- Service detected as Apache httpd 2.4.48.
- The http-server-header reveals the backend is likely Python/3.9.2 using Werkzeug/2.0.2.
- Web page title: 'GoodGames | Community and Store'.
- Internal hostname identified as 'goodgames.htb'.

<picture>

Figure #: Screenshot of Nmap output against goodgames.htb showing key evidence referenced above.

