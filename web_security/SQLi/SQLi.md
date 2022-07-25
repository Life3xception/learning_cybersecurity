# SQL Injection (SQLi)

## Definition

SQL injection (SQLi) is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database. It generally allows an attacker to view data that they are not normally able to retrieve. This might include data belonging to other users, or any other data that the application itself is able to access. In many cases, an attacker can modify or delete this data, causing persistent changes to the application's content or behavior.

In some situations, an attacker can escalate an SQL injection attack to compromise the underlying server or other back-end infrastructure, or perform a denial-of-service attack.

## Consequences

A successful SQL injection attack can result in unauthorized access to sensitive data, such as passwords, credit card details, or personal user information. Many high-profile data breaches in recent years have been the result of SQL injection attacks, leading to reputational damage and regulatory fines. In some cases, an attacker can obtain a persistent backdoor into an organization's systems, leading to a long-term compromise that can go unnoticed for an extended period.

## Retrieving hidden data

### SQLi in WHERE clause

If the url of a site is like the following

``
https://insecure-website.com/products?category=Gifts
``

and probably the SQL query that the request fires is

``
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
``

an attacker could construct the attack in the following ways:

``
https://insecure-website.com/products?category=Gifts'--
``

to see all the products of the category `Gifts`, because the query becomes

``
SELECT * FROM products WHERE category = 'Gifts'--' AND released = 1
``

otherwise, going further

``
https://insecure-website.com/products?category=Gifts'+OR+1=1--
``

to see all the products in any category, including categories that they don't know about, because the query becomes

``
SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1
``

and 1=1 is always true, for every item in the table `products`.

<!-- arrived at https://portswigger.net/web-security/sql-injection - Subverting application logic [TODO] -->