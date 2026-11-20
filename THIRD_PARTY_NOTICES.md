# Third-party notices

## D2K source

The D2K C source is copyright 2026 Necronicle and is distributed under the
MIT license below.

MIT License

Copyright (c) 2026 Necronicle

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## OpenSSL

The D2K controller and optional Telegram tunnel runtime statically link OpenSSL 3.5.8 from
upstream commit `f4dc4d58b48d346a8270183f89acf826d459b0ca`. OpenSSL is licensed
under the Apache License 2.0. [License text](licenses/Apache-2.0.txt)

`files/tg-roots.pem` contains the public ISRG Root X1 and ISRG Root X2 trust
anchors published by Internet Security Research Group (ISRG) for the relay's
Let's Encrypt certificate chain. Inclusion adds trust anchors without
disabling certificate-chain or hostname verification.

## Web panel: fonts and animation library

- `internal/web/assets/fonts/onest.woff2` — Onest (The Onest Project Authors),
  subset to Latin/Cyrillic; SIL Open Font License 1.1, text in `fonts/OFL-onest.txt`.
- `internal/web/assets/fonts/jbmono.woff2` — JetBrains Mono (The JetBrains Mono
  Project Authors), same subset; SIL Open Font License 1.1, text in `fonts/OFL-jbmono.txt`.
- `internal/web/assets/gsap.js` — GSAP 3.15.0 core with the Flip, MotionPathPlugin,
  DrawSVGPlugin, MorphSVGPlugin, ScrollToPlugin, SplitText, CustomEase and CustomWiggle
  files from the public `gsap` npm package, concatenated unmodified with
  their original copyright headers. Copyright GreenSock; distributed under the GreenSock
  standard "no charge" license, https://gsap.com/standard-license. The panel loads it
  from the router itself; without it the panel works without transitions.
