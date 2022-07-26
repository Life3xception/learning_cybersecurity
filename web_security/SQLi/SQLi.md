# SQL Injection (SQLi)

**Useful**: here is a [cheat sheet for SQLi](https://portswigger.net/web-security/sql-injection/cheat-sheet).

&nbsp;

## Definition

SQL injection (SQLi) is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database. It generally allows an attacker to view data that they are not normally able to retrieve. This might include data belonging to other users, or any other data that the application itself is able to access. In many cases, an attacker can modify or delete this data, causing persistent changes to the application's content or behavior.

In some situations, an attacker can escalate an SQL injection attack to compromise the underlying server or other back-end infrastructure, or perform a denial-of-service attack.

&nbsp;

## Consequences

A successful SQL injection attack can result in unauthorized access to sensitive data, such as passwords, credit card details, or personal user information. Many high-profile data breaches in recent years have been the result of SQL injection attacks, leading to reputational damage and regulatory fines. In some cases, an attacker can obtain a persistent backdoor into an organization's systems, leading to a long-term compromise that can go unnoticed for an extended period.

&nbsp;

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

&nbsp;

## Subverting application logic

If a web application uses a query similar to the following one for user's login

``
SELECT * FROM users WHERE username = 'wiener' AND password = 'bluecheese'
``

which returns the details of the user if the login is successfull, an attacker can log in as any user and without the need of a password using the SQL comment sequence -- to remove the check of the password.
The query becomes

``
SELECT * FROM users WHERE username = 'administrator'--' AND password = ''
``

&nbsp;

## Retrieving data from other database tables

In cases where the results of an SQL query are returned within the application's responses, an attacker can leverage an SQL injection vulnerability to retrieve data from other tables within the database. This is done using the UNION keyword, which lets you execute an additional SELECT query and append the results to the original query. \
For example, if an application executes the following query containing the user input "Gifts":

``
SELECT name, description FROM products WHERE category = 'Gifts'
``

then an attacker can submit the input:

``
' UNION SELECT username, password FROM users--
``

This will cause the application to return all usernames and passwords along with the names and descriptions of products.

Read more [SQLi UNION attacks](SQLi_union_attacks.md).

&nbsp;

## Examining the database

Following initial identification of an SQL injection vulnerability, it is generally useful to obtain some information about the database itself. This information can often pave the way for further exploitation.

You can query the version details for the database. The way that this is done depends on the database type, so you can infer the database type from whichever technique works. For example, on Oracle you can execute:

``
SELECT * FROM v$version
``

You can also determine what database tables exist, and which columns they contain. For example, on most databases you can execute the following query to list the tables:

``
SELECT * FROM information_schema.tables
``

Read more [Examining the database in SQL injections attacks](SQLi_examining_database.md).

&nbsp;

## Blind SQL injection vulnerabilities

Many instances of SQL injection are blind vulnerabilities. This means that the application does not return the results of the SQL query or the details of any database errors within its responses. Blind vulnerabilities can still be exploited to access unauthorized data, but the techniques involved are generally more complicated and difficult to perform.

Depending on the nature of the vulnerability and the database involved, the following techniques can be used to exploit blind SQL injection vulnerabilities:

- You can change the logic of the query to trigger a detectable difference in the application's response depending on the truth of a single condition. This might involve injecting a new condition into some Boolean logic, or conditionally triggering an error such as a divide-by-zero.

- You can conditionally trigger a time delay in the processing of the query, allowing you to infer the truth of the condition based on the time that the application takes to respond.

- You can trigger an out-of-band network interaction, using [OAST](https://portswigger.net/burp/application-security-testing/oast) techniques. This technique is extremely powerful and works in situations where the other techniques do not. Often, you can directly exfiltrate data via the out-of-band channel, for example by placing the data into a DNS lookup for a domain that you control.

Read more [Blind SQL injection](SQLi_blind.md).

&nbsp;

## How to detect SQL injection vulnerabilities

The majority of SQL injection vulnerabilities can be found quickly and reliably using Burp Suite's web vulnerability scanner.

SQL injection can be detected manually by using a systematic set of tests against every entry point in the application. This typically involves:

- Submitting the single quote character ' and looking for errors or other anomalies.

- Submitting some SQL-specific syntax that evaluates to the base (original) value of the entry point, and to a different value, and looking for systematic differences in the resulting application responses.

- Submitting Boolean conditions such as `OR 1=1` and `OR 1=2`, and looking for differences in the application's responses.

- Submitting payloads designed to trigger time delays when executed within an SQL query, and looking for differences in the time taken to respond.

- Submitting OAST payloads designed to trigger an out-of-band network interaction when executed within an SQL query, and monitoring for any resulting interactions.

&nbsp;

## SQL injection in different parts of the query

Most SQL injection vulnerabilities arise within the `WHERE` clause of a `SELECT` query. This type of SQL injection is generally well-understood by experienced testers.

But SQL injection vulnerabilities can in principle occur at any location within the query, and within different query types. The most common other locations where SQL injection arises are:

- In `UPDATE` statements, within the updated values or the `WHERE` clause.

- In `INSERT` statements, within the inserted values.

- In `SELECT` statements, within the table or column name.

- In `SELECT` statements, within the `ORDER BY` clause.

&nbsp;

## SQL injection in different contexts

In all of the labs so far, you've used the query string to inject your malicious SQL payload. However, it's important to note that you can perform SQL injection attacks using any controllable input that is processed as a SQL query by the application. For example, some websites take input in JSON or XML format and use this to query the database.

These different formats may even provide alternative ways for you to [obfuscate attacks](https://portswigger.net/web-security/reference/obfuscating-attacks-using-encodings#obfuscation-via-xml-encoding) that are otherwise blocked due to WAFs and other defense mechanisms. Weak implementations often just look for common SQL injection keywords within the request, so you may be able to bypass these filters by simply encoding or escaping characters in the prohibited keywords. For example, the following XML-based SQL injection uses an XML escape sequence to encode the S character in `SELECT`:

```xml
<stockCheck>
    <productId>
        ' &#x53;ELECT * FROM information_schema.tables--
    </productId>
    <storeId>
        123
    </storeId>
</stockCheck>
```

This will be decoded server-side before being passed to the SQL interpreter.

&nbsp;

## Second-order SQL injection

*First-order SQL* injection arises where the application takes user input from an HTTP request and, in the course of processing that request, incorporates the input into an SQL query in an unsafe way.

In *second-order SQL injection* (also known as stored SQL injection), the application takes user input from an HTTP request and stores it for future use. This is usually done by placing the input into a database, but no vulnerability arises at the point where the data is stored. Later, when handling a different HTTP request, the application retrieves the stored data and incorporates it into an SQL query in an unsafe way.

Second-order SQL injection often arises in situations where developers are aware of SQL injection vulnerabilities, and so safely handle the initial placement of the input into the database. When the data is later processed, it is deemed to be safe, since it was previously placed into the database safely. At this point, the data is handled in an unsafe way, because the developer wrongly deems it to be trusted.

&nbsp;

## Database-specific factors

Some core features of the SQL language are implemented in the same way across popular database platforms, and so many ways of detecting and exploiting SQL injection vulnerabilities work identically on different types of database.

However, there are also many differences between common databases. These mean that some techniques for detecting and exploiting SQL injection work differently on different platforms. For example:

- Syntax for string concatenation.

- Comments.

- Batched (or stacked) queries.

- Platform-specific APIs.

- Error messages.

Find more on the cheat sheet at the start of this file.

&nbsp;

# How to prevent SQL injection

Most instances of SQL injection can be prevented by using parameterized queries (also known as prepared statements) instead of string concatenation within the query.

The following code is vulnerable to SQL injection because the user input is concatenated directly into the query:

```[java]
String query = "SELECT * FROM products WHERE category = '"+ input + "'";
Statement statement = connection.createStatement();
ResultSet resultSet = statement.executeQuery(query);
```

This code can be easily rewritten in a way that prevents the user input from interfering with the query structure:

```[java]
PreparedStatement statement = connection.prepareStatement("SELECT * FROM products WHERE category = ?");
statement.setString(1, input);
ResultSet resultSet = statement.executeQuery();
```

Parameterized queries can be used for any situation where untrusted input appears as data within the query, including the `WHERE` clause and values in an `INSERT` or `UPDATE` statement. They can't be used to handle untrusted input in other parts of the query, such as table or column names, or the `ORDER BY` clause. Application functionality that places untrusted data into those parts of the query will need to take a different approach, such as white-listing permitted input values, or using different logic to deliver the required behavior.

For a parameterized query to be effective in preventing SQL injection, the string that is used in the query must always be a hard-coded constant, and must never contain any variable data from any origin. Do not be tempted to decide case-by-case whether an item of data is trusted, and continue using string concatenation within the query for cases that are considered safe. It is all too easy to make mistakes about the possible origin of data, or for changes in other code to violate assumptions about what data is tainted.
