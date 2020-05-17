---
title: "MemLabs - Lab2"
classes: wide
header:
  teaser: /assets/images/ctf-writeups/memlabs/logo.png
ribbon: MidnightBlue
description: "One of the clients of our company, lost the access to his system due  to an unknown error. He is supposedly a very popular 'environmental'  activist. As a part of the investigation, he told us that his go to  applications are browsers, his password managers etc. We hope that you  can dig into this memory dump and find his important stuff and give it  back to us..."
categories:
  - CTF Writeups
---

> ## **Challenge Description**
>
> One of the clients of our company, lost the access to his system due  to an unknown error. He is supposedly a very popular "environmental"  activist. As a part of the investigation, he told us that his go to  applications are browsers, his password managers etc. We hope that you  can dig into this memory dump and find his important stuff and give it  back to us.
>
> **Note**: This challenge is composed of 3 flags.
>
> **Challenge file**: [MemLabs_Lab2](https://mega.nz/#!ChoDHaja!1XvuQd49c7-7kgJvPXIEAst-NXi8L3ggwienE1uoZTk)

First we need to identify the operating system of the memory image.

```
$ volatility -f MemoryDump_Lab2.raw imageinfo
```

[![1](/assets/images/ctf-writeups/memlabs/lab2/1.png)](/assets/images/ctf-writeups/memlabs/lab2/1.png)

Next, let's check the processes list.

```
$ volatility -f MemoryDump_Lab2.raw --profile Win7SP1x64 pslist
```

[![2](/assets/images/ctf-writeups/memlabs/lab2/2.png)](/assets/images/ctf-writeups/memlabs/lab2/2.png)

We can see interesting processes like `chrome` and `KeePass`. but first let's look back at the description, note the quoted word `"environmental"`. I think it's a hint for environment variables, so let's go down this way first.

```
$ volatility -f MemoryDump_Lab2.raw --profile Win7SP1x64 envars
........
320 csrss.exe      0x0000000000481320    NEW_TMP    C:\Windows\ZmxhZ3t3M2xjMG0zX1QwXyRUNGczXyFfT2ZfTDRCXzJ9
........
424 wininit.exe    0x000000000030a600    NEW_TMP    C:\Windows\ZmxhZ3t3M2xjMG0zX1QwXyRUNGczXyFfT2ZfTDRCXzJ9
........
812 svchost.exe    0x0000000000221320    NEW_TMP    C:\Windows\ZmxhZ3t3M2xjMG0zX1QwXyRUNGczXyFfT2ZfTDRCXzJ9
........
```

We can see the environment variable `NEW_TMP` in every process with a value that looks like Base64. so let's decode it.

```
$ echo ZmxhZ3t3M2xjMG0zX1QwXyRUNGczXyFfT2ZfTDRCXzJ9 | base64 -d
flag{w3lc0m3_T0_$T4g3_!_Of_L4B_2}
```

Great, first stage is done.

> #### Flag 1: flag{w3lc0m3_T0\_$T4g3\_!\_Of_L4B_2}

Next, let's check this `KeePass` process, looks like a password manager.

After some googling, I learned that KeePass stores the passwords in a database with the extension `".kdbx"` and looks it with a master password.

So let's check if this database is in memory.

```
$ volatility -f MemoryDump_Lab2.raw --profile Win7SP1x64 filescan | grep ".kdbx"
Volatility Foundation Volatility Framework 2.6.1
0x000000003fb112a0     16      0 R--r-- \Device\HarddiskVolume2\Users\SmartNet\Secrets\Hidden.kdbx
```

And here it's, now let's dump it.

```
$ volatility -f MemoryDump_Lab2.raw --profile Win7SP1x64 dumpfiles -Q 0x000000003fb112a0 -D lab2_output/
Volatility Foundation Volatility Framework 2.6.1
DataSectionObject 0x3fb112a0   None   \Device\HarddiskVolume2\Users\SmartNet\Secrets\Hidden.kdbx
```

The only thing left is to get the master password, I tried scanning files for any password like file.

```
$ volatility -f MemoryDump_Lab2.raw --profile Win7SP1x64 filescan | grep -i "password"
Volatility Foundation Volatility Framework 2.6.1
.........
0x000000003fce1c70      1      0 R--r-d \Device\HarddiskVolume2\Users\Alissa Simpson\Pictures\Password.png
.........
```

Look at that, an image named Password!!! looks interesting, let's dump it.

```
$ volatility -f MemoryDump_Lab2.raw --profile Win7SP1x64 dumpfiles -Q 0x000000003fce1c70 -D lab2_output/
Volatility Foundation Volatility Framework 2.6.1
DataSectionObject 0x3fce1c70   None   \Device\HarddiskVolume2\Users\Alissa Simpson\Pictures\Password.png
```

[![3](/assets/images/ctf-writeups/memlabs/lab2/3.png)](/assets/images/ctf-writeups/memlabs/lab2/3.png)

If you look closely at the bottom right, you can spot the password.

Now let's use this password to open the database in KeePass.

[![4](/assets/images/ctf-writeups/memlabs/lab2/4.png)](/assets/images/ctf-writeups/memlabs/lab2/4.png) | [![5](/assets/images/ctf-writeups/memlabs/lab2/5.png)](/assets/images/ctf-writeups/memlabs/lab2/5.png)

The flag is the copied password.

> #### Flag 2: flag{w0w_th1s_1s_Th3_SeC0nD_ST4g3_!!}

Now let's return back the the `chrome` process, the first thing is to check the browsing history.

This amazing github repo has the plugin we need: [Volatility-Plugins](https://github.com/superponible/volatility-plugins)

```
volatility --plugins=plugins/ -f MemoryDump_Lab2.raw --profile Win7SP1x64 chromehistory > chromehistory.txt
```

[![6](/assets/images/ctf-writeups/memlabs/lab2/6.png)](/assets/images/ctf-writeups/memlabs/lab2/6.png)

We have a mega link, the mega folder name is `MemLabs_Lab2_Stage3` and it contained a single zip file named `Important.zip` (password protected).

I tried unzipping it with `unzip` but it gave me an error, so I used `7z`.

[![7](/assets/images/ctf-writeups/memlabs/lab2/7.png)](/assets/images/ctf-writeups/memlabs/lab2/7.png)

Let's get the password.

```
$ echo -n flag{w3ll_3rd_stage_was_easy} | sha1sum 
6045dd90029719a039fd2d2ebcca718439dd100a
```

After unzipping the file, I got this image.

[![8](/assets/images/ctf-writeups/memlabs/lab2/8.png)](/assets/images/ctf-writeups/memlabs/lab2/8.png)

> #### Flag 3: flag{oK_So_Now_St4g3_3_is_DoNE!!}