---
title: "MemLabs - Lab6"
classes: wide
header:
  teaser: /assets/images/ctf-writeups/memlabs/logo.png
ribbon: MidnightBlue
description: "Note: This challenge is composed of 1 flag.
The flag format for this lab is: inctf{s0me_l33t_Str1ng}..."
categories:
  - CTF Writeups
---

> ## **Challenge Description**
>
> **Note**: This challenge is composed of 1 flag.
>
> The flag format for this lab is: **inctf{s0me_l33t_Str1ng}**
>
> **Challenge file**: [MemLabs_Lab6](https://mega.nz/#!C0pjUKxI!LnedePAfsJvFgD-Uaa4-f1Tu0kl5bFDzW6Mn2Ng6pnM)

First we need to identify the operating system of the memory image.

```
$ volatility -f MemoryDump_Lab6.raw imageinfo
```

[![1](/assets/images/ctf-writeups/memlabs/lab6/1.png)](/assets/images/ctf-writeups/memlabs/lab6/1.png)

Next, let's check the running processes.

```
$ volatility -f MemoryDump_Lab6.raw --profile Win7SP1x64 pslist
```

[![2](/assets/images/ctf-writeups/memlabs/lab6/2.png)](/assets/images/ctf-writeups/memlabs/lab6/2.png)

We can see some interesting processes here like `WinRAR`, `chrome` and `firefox` so let's start with `WinRAR`.

```
$ volatility --plugins=plugins/ -f MemoryDump_Lab6.raw --profile Win7SP1x64 cmdline | grep WinRAR.exe
Volatility Foundation Volatility Framework 2.6.1
WinRAR.exe pid:   3716
Command line : "C:\Program Files\WinRAR\WinRAR.exe" "C:\Users\Jaffa\Desktop\pr0t3ct3d\flag.rar"
```

Oh, that file name is interesting, let's dump it.

```
$ volatility -f MemoryDump_Lab6.raw --profile Win7SP1x64 filescan | grep flag.rar
Volatility Foundation Volatility Framework 2.6.1
0x000000005fcfc4b0     16      0 R--rwd \Device\HarddiskVolume2\Users\Jaffa\Desktop\pr0t3ct3d\flag.rar

$ volatility -f MemoryDump_Lab6.raw --profile Win7SP1x64 dumpfiles -Q 0x000000005fcfc4b0 -D lab6_output/
Volatility Foundation Volatility Framework 2.6.1
DataSectionObject 0x5fcfc4b0   None   \Device\HarddiskVolume2\Users\Jaffa\Desktop\pr0t3ct3d\flag.rar
```

Next, let's try to unrar it.

```
$ unrar e flag.rar 
UNRAR 5.61 beta 1 freeware      Copyright (c) 1993-2018 Alexander Roshal
Extracting from flag.rar
Enter password (will not be echoed) for flag2.png: 
```

Of course it's encrypted :(

Let's take a step back and try more plugins.

```
$ volatility --plugins=plugins/ -f MemoryDump_Lab6.raw --profile Win7SP1x64 consoles
```

[![3](/assets/images/ctf-writeups/memlabs/lab6/3.png)](/assets/images/ctf-writeups/memlabs/lab6/3.png)

I noticed the author is running `env` command, I suspect it's a hint for us.

So let's try dumping the environment variables for `WinRAR`.

[![4](/assets/images/ctf-writeups/memlabs/lab6/4.png)](/assets/images/ctf-writeups/memlabs/lab6/4.png)

Awesome, not we now that the rar password is: `easypeasyvirus`.

```
$ unrar e flag.rar 
UNRAR 5.61 beta 1 freeware      Copyright (c) 1993-2018 Alexander Roshal
Extracting from flag.rar
Enter password (will not be echoed) for flag2.png: 
Extracting  flag2.png                                                 OK 
All OK
```

[![5](/assets/images/ctf-writeups/memlabs/lab6/5.png)](/assets/images/ctf-writeups/memlabs/lab6/5.png)

Great, that looks like the second half of the flag.

> #### Second half: aN_Am4zINg\_!\_i_gU3Ss???_}

Let's return back the the chrome process, the first thing is to check the browsing history.

This amazing github repo has the plugin we need: [Volatility-Plugins](https://github.com/superponible/volatility-plugins)

```
$ volatility --plugins=plugins/ -f MemoryDump_Lab6.raw --profile Win7SP1x64 chromehistory > chromehistory.txt
```

Scrolling through the history dump, I notices a pastebin link (`https://pastebin.com/RSGSi1hk`).

[![6](/assets/images/ctf-writeups/memlabs/lab6/6.png)](/assets/images/ctf-writeups/memlabs/lab6/6.png)

Here is what I found.

[![7](/assets/images/ctf-writeups/memlabs/lab6/7.png)](/assets/images/ctf-writeups/memlabs/lab6/7.png)

There is a link to a google drive doc along with the note `David sent the key in mail`.

The doc file is just some lorem ipsum text, but if you look carefully you can see a mega link (took me a while).

[![8](/assets/images/ctf-writeups/memlabs/lab6/8.png)](/assets/images/ctf-writeups/memlabs/lab6/8.png)

Let's see what this mega link has.

[![9](/assets/images/ctf-writeups/memlabs/lab6/9.png)](/assets/images/ctf-writeups/memlabs/lab6/9.png)

Another password, I hate my life :(

At this point I got stuck, so I tried every volatility plugin I know about. Then the magic happened.

The `screenshot` plugin saved the day.

```
$ volatility --plugins=plugins/ -f MemoryDump_Lab6.raw --profile Win7SP1x64 screenshot -D lab6_output
```

It dumped 13 images, all of them are just white images except for this one.

[![10](/assets/images/ctf-writeups/memlabs/lab6/10.png)](/assets/images/ctf-writeups/memlabs/lab6/10.png)

There is a windows with the title `Mega Drive Key ....`, that looks promising. so let's search for this string in memory.

```
$ strings MemoryDump_Lab6.raw | grep "Mega Drive Key"
.........
Mega Drive Key - davidbenjamin939@gmail.com - Gmail
top['GM_TRACING_THREAD_DETAILS_CHUNK_START'] = (window.performance && window.performance.now) ? window.performance.now() : null; top._GM_setData({"Cl6csf":[["simls",0,"{\"2\":[{\"1\":0,\"2\":{\"1\":\"Mega Drive Key\",\"2\":\"THE KEY IS zyWxCjCYYSEMA-hZe552qWVXiPwa5TecODbjnsscMIU\"
.........
```

Look at that, we got the key (a good pair of eyes required). the key is: `zyWxCjCYYSEMA-hZe552qWVXiPwa5TecODbjnsscMIU`.

After decrypting the file, it turned out to be an image. but unfortunately it was corrupted.

Opening it with hexedit, the IHDR part was corrupted (iHDR). so all we need to do is to change `i (69)` to `I (49)`.

[![11](/assets/images/ctf-writeups/memlabs/lab6/11.png)](/assets/images/ctf-writeups/memlabs/lab6/11.png)

Finally we got the first part of the flag, that was a long journey.

[![12](/assets/images/ctf-writeups/memlabs/lab6/12.png)](/assets/images/ctf-writeups/memlabs/lab6/12.png)

> #### Flag: inctf{thi5_cH4LL3Ng3\_!s_g0nn4_b3\_?\_aN_Am4zINg\_!\_i\_gU3Ss???_}