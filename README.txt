AMAROK PAGES V2 — FIX CLOUDFLARE 308
====================================

FIX UTAMA
---------
Versi lama mengambil template via:

  env.ASSETS.fetch("/index.html")

Cloudflare Pages meng-canonicalize /index.html -> / dengan status 308.
Karena root project sengaja 404, hasilnya terlihat seperti:

  /gacorr1 -> 308 -> / -> 404

Versi V2 memakai:

  /gate-template.txt

lalu Worker mengirim isinya sebagai text/html.

STRUKTUR REPO
-------------
_worker.js
gate-template.txt
jembot.js
wrangler.toml
README.txt

Hapus index.html lama agar tidak membingungkan.

REDIRECT
--------
Edit _worker.js:

redirects: {
  "gacorr1": "https://example.com/"
}

SECRET
------
Versi V2 WAJIB memakai Cloudflare Secret:

AMAROK_SECRET

Tidak ada embedded secret lagi.

TEST
----
1. Challenge:
https://PROJECT.pages.dev/amarok/gate/challenge?code=gacorr1

2. Gate:
https://PROJECT.pages.dev/gacorr1

Expected:
gate loader -> PoW -> 204 Set-Cookie -> reload /gacorr1 -> 302 destination

CLOUDFLARE GIT
--------------
Commit file ke branch main.
Cloudflare Pages yang sudah Connect to Git akan deploy otomatis.
