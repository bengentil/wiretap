# wiretap

## Description

wiretap is CLI utility to capture data before/after it has been en/decrypted by openssl.
The capture is done by attaching eBPF uprobes to SSL_read & SSL_write functions.

## Goals

Be able, **as the root user**, to inspect data in APIs connections in a end-to-end TLS setup,
without:
- Altering a program (adding logs)
- Increasing the log level / slowing down execution / generating too much data
- The need to expose the keys via the [`SSLKEYLOGFILE` environment variable](https://wiki.wireshark.org/TLS#using-the-pre-master-secret)

## Non-Goals

Exploit openssl, capture keys, decrypt captured TLS data, give access to data that you don't already own.

## Usage

```
wiretap [-o=<output>] [<probe...>]

<output> only stdout for now
<probe> is <probe_name>:<symbol>:<executable>
<probe_name> only openssl for now
<symbol> symbol to attach the probe
<executable> file to lookup the symbol
```

Without arguments, wiretap run with those probes:
- openssl:SSL_read:/lib64/libssl.so
- openssl:SSL_write:/lib64/libssl.so

## Example

```
2022/05/21 10:57:27 [openssl:SSL_write:/lib64/libssl.so.3] returned in curl(1720), len=74
00000000  47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a  |GET / HTTP/1.1..|
00000010  48 6f 73 74 3a 20 67 6f  6f 67 6c 65 2e 63 6f 6d  |Host: google.com|
00000020  0d 0a 55 73 65 72 2d 41  67 65 6e 74 3a 20 63 75  |..User-Agent: cu|
00000030  72 6c 2f 37 2e 38 32 2e  30 0d 0a 41 63 63 65 70  |rl/7.82.0..Accep|
00000040  74 3a 20 2a 2f 2a 0d 0a  0d 0a                    |t: */*....|
2022/05/21 10:57:27 [openssl:SSL_read:/lib64/libssl.so.3] returned in curl(1720), len=256
00000000  48 54 54 50 2f 31 2e 31  20 33 30 31 20 4d 6f 76  |HTTP/1.1 301 Mov|
00000010  65 64 20 50 65 72 6d 61  6e 65 6e 74 6c 79 0d 0a  |ed Permanently..|
00000020  4c 6f 63 61 74 69 6f 6e  3a 20 68 74 74 70 73 3a  |Location: https:|
00000030  2f 2f 77 77 77 2e 67 6f  6f 67 6c 65 2e 63 6f 6d  |//www.google.com|
00000040  2f 0d 0a 43 6f 6e 74 65  6e 74 2d 54 79 70 65 3a  |/..Content-Type:|
00000050  20 74 65 78 74 2f 68 74  6d 6c 3b 20 63 68 61 72  | text/html; char|
00000060  73 65 74 3d 55 54 46 2d  38 0d 0a 44 61 74 65 3a  |set=UTF-8..Date:|
00000070  20 53 61 74 2c 20 32 31  20 4d 61 79 20 32 30 32  | Sat, 21 May 202|
00000080  32 20 31 32 3a 30 38 3a  35 32 20 47 4d 54 0d 0a  |2 12:08:52 GMT..|
00000090  45 78 70 69 72 65 73 3a  20 53 61 74 2c 20 32 31  |Expires: Sat, 21|
000000a0  20 4d 61 79 20 32 30 32  32 20 31 32 3a 30 38 3a  | May 2022 12:08:|
000000b0  35 32 20 47 4d 54 0d 0a  43 61 63 68 65 2d 43 6f  |52 GMT..Cache-Co|
000000c0  6e 74 72 6f 6c 3a 20 70  72 69 76 61 74 65 2c 20  |ntrol: private, |
000000d0  6d 61 78 2d 61 67 65 3d  32 35 39 32 30 30 30 0d  |max-age=2592000.|
000000e0  0a 53 65 72 76 65 72 3a  20 67 77 73 0d 0a 43 6f  |.Server: gws..Co|
000000f0  6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 32 32  |ntent-Length: 22|
2022/05/21 10:57:27 [openssl:SSL_read:/lib64/libssl.so.3] returned in curl(1720), len=256
00000000  30 0d 0a 58 2d 58 53 53  2d 50 72 6f 74 65 63 74  |0..X-XSS-Protect|
00000010  69 6f 6e 3a 20 30 0d 0a  58 2d 46 72 61 6d 65 2d  |ion: 0..X-Frame-|
00000020  4f 70 74 69 6f 6e 73 3a  20 53 41 4d 45 4f 52 49  |Options: SAMEORI|
00000030  47 49 4e 0d 0a 53 65 74  2d 43 6f 6f 6b 69 65 3a  |GIN..Set-Cookie:|
00000040  20 43 4f 4e 53 45 4e 54  3d 50 45 4e 44 49 4e 47  | CONSENT=PENDING|
00000050  2b 33 31 35 3b 20 65 78  70 69 72 65 73 3d 4d 6f  |+315; expires=Mo|
00000060  6e 2c 20 32 30 2d 4d 61  79 2d 32 30 32 34 20 31  |n, 20-May-2024 1|
00000070  32 3a 30 38 3a 35 32 20  47 4d 54 3b 20 70 61 74  |2:08:52 GMT; pat|
00000080  68 3d 2f 3b 20 64 6f 6d  61 69 6e 3d 2e 67 6f 6f  |h=/; domain=.goo|
00000090  67 6c 65 2e 63 6f 6d 3b  20 53 65 63 75 72 65 0d  |gle.com; Secure.|
000000a0  0a 50 33 50 3a 20 43 50  3d 22 54 68 69 73 20 69  |.P3P: CP="This i|
000000b0  73 20 6e 6f 74 20 61 20  50 33 50 20 70 6f 6c 69  |s not a P3P poli|
000000c0  63 79 21 20 53 65 65 20  67 2e 63 6f 2f 70 33 70  |cy! See g.co/p3p|
000000d0  68 65 6c 70 20 66 6f 72  20 6d 6f 72 65 20 69 6e  |help for more in|
000000e0  66 6f 2e 22 0d 0a 41 6c  74 2d 53 76 63 3a 20 68  |fo."..Alt-Svc: h|
000000f0  33 3d 22 3a 34 34 33 22  3b 20 6d 61 3d 32 35 39  |3=":443"; ma=259|
2022/05/21 10:57:27 [openssl:SSL_read:/lib64/libssl.so.3] returned in curl(1720), len=256
00000000  32 30 30 30 2c 68 33 2d  32 39 3d 22 3a 34 34 33  |2000,h3-29=":443|
00000010  22 3b 20 6d 61 3d 32 35  39 32 30 30 30 2c 68 33  |"; ma=2592000,h3|
00000020  2d 51 30 35 30 3d 22 3a  34 34 33 22 3b 20 6d 61  |-Q050=":443"; ma|
00000030  3d 32 35 39 32 30 30 30  2c 68 33 2d 51 30 34 36  |=2592000,h3-Q046|
00000040  3d 22 3a 34 34 33 22 3b  20 6d 61 3d 32 35 39 32  |=":443"; ma=2592|
00000050  30 30 30 2c 68 33 2d 51  30 34 33 3d 22 3a 34 34  |000,h3-Q043=":44|
00000060  33 22 3b 20 6d 61 3d 32  35 39 32 30 30 30 2c 71  |3"; ma=2592000,q|
00000070  75 69 63 3d 22 3a 34 34  33 22 3b 20 6d 61 3d 32  |uic=":443"; ma=2|
00000080  35 39 32 30 30 30 3b 20  76 3d 22 34 36 2c 34 33  |592000; v="46,43|
00000090  22 0d 0a 0d 0a 3c 48 54  4d 4c 3e 3c 48 45 41 44  |"....<HTML><HEAD|
000000a0  3e 3c 6d 65 74 61 20 68  74 74 70 2d 65 71 75 69  |><meta http-equi|
000000b0  76 3d 22 63 6f 6e 74 65  6e 74 2d 74 79 70 65 22  |v="content-type"|
000000c0  20 63 6f 6e 74 65 6e 74  3d 22 74 65 78 74 2f 68  | content="text/h|
000000d0  74 6d 6c 3b 63 68 61 72  73 65 74 3d 75 74 66 2d  |tml;charset=utf-|
000000e0  38 22 3e 0a 3c 54 49 54  4c 45 3e 33 30 31 20 4d  |8">.<TITLE>301 M|
000000f0  6f 76 65 64 3c 2f 54 49  54 4c 45 3e 3c 2f 48 45  |oved</TITLE></HE|
2022/05/21 10:57:27 [openssl:SSL_read:/lib64/libssl.so.3] returned in curl(1720), len=113
00000000  41 44 3e 3c 42 4f 44 59  3e 0a 3c 48 31 3e 33 30  |AD><BODY>.<H1>30|
00000010  31 20 4d 6f 76 65 64 3c  2f 48 31 3e 0a 54 68 65  |1 Moved</H1>.The|
00000020  20 64 6f 63 75 6d 65 6e  74 20 68 61 73 20 6d 6f  | document has mo|
00000030  76 65 64 0a 3c 41 20 48  52 45 46 3d 22 68 74 74  |ved.<A HREF="htt|
00000040  70 73 3a 2f 2f 77 77 77  2e 67 6f 6f 67 6c 65 2e  |ps://www.google.|
00000050  63 6f 6d 2f 22 3e 68 65  72 65 3c 2f 41 3e 2e 0d  |com/">here</A>..|
00000060  0a 3c 2f 42 4f 44 59 3e  3c 2f 48 54 4d 4c 3e 0d  |.</BODY></HTML>.|
00000070  0a                                                |.|
```

## Acknowledgments

- https://confused.ai/posts/intercepting-zoom-tls-encryption-bpf-uprobes
- https://github.com/cilium/ebpf