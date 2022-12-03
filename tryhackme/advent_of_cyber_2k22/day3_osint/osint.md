# OSINT

OSINT is gathering and analysing publicly available data for intelligence purposes, which includes information collected from the internet, mass media, specialist journals and research, photos, and geospatial information.

## OSINT Techniques

### Google Dorks

Google Dorking involves using specialist search terms and advanced search operators to find results that are not usually displayed using regular search terms. 

Some of the widely used Google dorks are mentioned below:

- inurl: Searches for a specified text in all indexed URLs. For example, `inurl:hacking` will fetch all URLs containing the word "hacking".
- filetype: Searches for specified file extensions. For example, `filetype:pdf "hacking"` will bring all pdf files containing the word "hacking".
- site: Searches all the indexed URLs for the specified domain. For example, `site:tryhackme.com` will bring all the indexed URLs from `tryhackme.com`.
- cache: Get the latest cached version by the Google search engine. For example, `cache:tryhackme.com`.

For example, you can use the dork `site:github.com "DB_PASSWORD"` to search only in `github.com` and look for the string `DB_PASSWORD` (possible database credentials).

### WHOIS Lookup

WHOIS database stores public domain information such as registrant (domain owner), administrative, billing and technical contacts in a centralised database. Bad actors can, later on, use the information for profiling, spear phishing campaigns (targeting selected individuals) etc. 

### Robots.txt

The robots.txt is a publicly accessible file created by the website administrator and intended for search engines to allow or disallow indexing of the website's URLs. All websites have their robots.txt file directly accessible through the domain's main URL. It is a kind of communication mechanism between websites and search engine crawlers. 

### Breached Database Search

Major social media and tech giants have suffered data breaches in the past.  As a result, the leaked data is publicly available and, most of the time contains PII like usernames, email addresses, mobile numbers and even passwords. Users may use the same password across all the websites; that enables bad actors to re-use the same password against a user on a different platform for a complete account takeover. Many web services offer to check if your email address or phone number is in a leaked database; HaveIBeenPwned is one of the free services. 

### Searching GitHub Repos

GitHub is a renowned platform that allows developers to host their code through version control. A developer can create multiple repositories and set the privacy setting as well. A common flaw by developers is that the privacy of the repository is set as public, which means anyone can access it. These repositories contain complete source code and, most of the time, include passwords, access tokens, etc.
