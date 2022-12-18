---
title: "Writing x64dbg plugins"
classes: wide
header:
  teaser: /assets/images/tutorials/x64dbg/plugins/logo.png
ribbon: ForestGreen
description: "In the previous post we talked about writing x64dbg scripts, now let's dive deeper and write our own plugin to do the same..."
categories:
  - Tutorials
toc: true
---

In the [previous post](https://n1ght-w0lf.github.io/tutorials/writing-x64dbg-scripts) we talked about writing x64dbg scripts, now let's dive deeper and write our own plugin to do the same job (automatically dumping unpacked PE payloads in memory).

x64dbg comes with an integrated plugin SDK for creating plugins using C++.

## Setup

The easiest way to create a plugin is to use the [PluginTemplate](https://github.com/x64dbg/PluginTemplate) to create a new repository for your plugin.

Next you can edit `cmake.toml` which contains the project configuration, for this tutorial we will only change the `name` and `target` values to our plugin name.

```cmake
name = "EasyDump"
....
[target.EasyDump]
```

To build the project for 64-bit --> `build64\ProjectName.sln`

```
cmake -B build64 -A x64
cmake --build build64 --config Release
```

To build the project for 32-bit --> `build32\ProjectName.sln`

```
cmake -B build32 -A Win32
cmake --build build32 --config Release
```

## Plugin structure

A plugin must have an exported function called `pluginit`, this is the first function that gets called when the plugin is loaded and where the plugin data is initialized.

Other optional exports are:

-  `plugstop`:

  called when the plugin is about to be unloaded and where the plugin data cleanup occurs.

- `plugsetup`:

  called when the plugin initialization was successful, here you can register menus and other GUI-related things.

## SDK functions

Before we go any further we need to know what functions exported by the plugin SDK we can use, you can find some of these functions in the official [docs](https://help.x64dbg.com/en/latest/developers/functions/index.html) but many of them are not documented.

To view the full list you can explore the SDK header files.

[![1](/assets/images/tutorials/x64dbg/plugins/1.png)](/assets/images/tutorials/x64dbg/plugins/1.png)

For me plugin SDK functions are divided into 4 main categories:

- \_plugin\_ functions @`_plugins.h`:

  Helper functions for plugin setup, initialization and logging.

- bridge functions @`bridgemain.h`:

  Bridge is the communication library for the DBG and GUI part of x64dbg.

- scriptapi functions @`_scriptapi_*.h`:

  It is intended to be used by plugins. It provides easy scripting experience for developers.

- TitanEngine functions @`TitanEngine.h`:

  Titan is the debugging engine for x64dbg.

Most functions are self explanatory or documented in the official docs, for TitanEngine functions you can find its docs [here](https://github.com/x64dbg/x64dbg/blob/development/src/dbg/TitanEngine/TitanEngine.txt) or you can check the markdown version for better readability I uploaded [here](https://gist.github.com/N1ght-W0lf/49c4141b52acf45434679602acb32f88).

Ok enough talk let's get our hands dirty.

## Implementation

Your code should go into `plugin.cpp` file, let's start with the plugin main components.

```c++
// Initialize your plugin data here.
bool pluginInit(PLUG_INITSTRUCT* initStruct)
{
    _plugin_logputs("[" PLUGIN_NAME "] Loaded successfully!");

    if (!_plugin_registercommand(pluginHandle, "EasyDump", cbEasyDump, true))
        return fail("Failed to register command");

    return true; // Return false to cancel loading the plugin.
}

// Deinitialize your plugin data here.
void pluginStop()
{
    _plugin_unregistercommand(pluginHandle, "EasyDump");
}
```

First we need to register a command that we can use in the command prompt using `_plugin_registercommand` function, The definition for this function is:

```c++
bool _plugin_registercommand(
	int pluginHandle,          // Plugin handle
	const char* command,       // Command name
	CBPLUGINCOMMAND cbCommand, // Callback function
	bool debugonly             // Restrict the command to debug-only
);
```

And of course don't forget to unregister this command inside `pluginStop` using `_plugin_unregistercommand`.

Now let's implement the callback function.

```c++
static bool cbEasyDump(int argc, char* argv[]) {
    // Delete All BPs
    DbgCmdExec("bpc");

    // Set BP on VirtualAlloc ret
    if (!SetAPIBreakPoint("kernelbase.dll", "VirtualAlloc", UE_BREAKPOINT, UE_APIEND, cbVirtualAlloc))
        fail("Failed to set a Breakpoint on VirtualAlloc");

    // Set BP on VirtualProtect start
    if (!SetAPIBreakPoint("kernelbase.dll", "VirtualProtect", UE_BREAKPOINT, UE_APISTART, cbVirtualProtect))
        fail("Failed to set a Breakpoint on VirtualProtect");

    _plugin_logprint("[" PLUGIN_NAME "] Starting the program...\n");
    DbgCmdExec("run");

    return true;
}
```

Callback arguments are passed in `argv` starting at index 1, but our command doesn't need any arguments.

We will start with deleting all breakpoints to let the plugin run without interruption using `DbgCmdExec` to execute `bpc` command (breakpoint clear).

Next we set our breakpoints using `SetAPIBreakPoint` function which is defined as:

```c++
bool __stdcall SetAPIBreakPoint(
    char* szDLLName,   // DLL name
    char* szAPIName,   // API name
    DWORD bpxType,     // UE_BREAKPOINT or UE_SINGLESHOOT
    DWORD bpxPlace,    // UE_APISTART or UE_APIEND
    LPVOID bpxCallBack // Callback function
);
```

For `VirtualAlloc` we need to set the breakpoint at return so we will use `UE_APIEND` as the `bpxPlace` value.

Next we do some logging and run the program.

```c++
// VirtualAlloc BP callback
static void cbVirtualAlloc() {
    mem_addr = Script::Register::GetCAX();
    // auto x = GetFunctionParameter(DbgGetProcessHandle(), UE_FUNCTION_STDCALL_RET, 2, UE_PARAMETER_DWORD);
    mem_size = DbgEval("arg.get(1)");

    _plugin_logprintf("[" PLUGIN_NAME "] VirtualAlloc addr: %x\n", mem_addr);
    _plugin_logprintf("[" PLUGIN_NAME "] VirtualAlloc size: %x\n", mem_size);
}
```

When reach the `VirtualAlloc` callback the allocated memory address would be stored at `EAX/RAX`, we can use the scriptapi register function `GetCAX` to read this value (remember x64dbg provides special registers for architecture-independent code).

To get the memory size stored at the second argument we can use `DbgEval` to evaluate `arg.get(1)` command and get its result.

```c++
// VirtualProtect BP callback
static void cbVirtualProtect() {
    auto header = Script::Memory::ReadWord(mem_addr);
    // Check for MZ header
    if (header == 0x5a4d) {
        _plugin_logprintf("[" PLUGIN_NAME "] Found a PE file at addr: %x\n", mem_addr);

        // Build dumping path
        char path[MAX_PATH];
        Script::Module::GetMainModulePath(path);
        sprintf(path, "%s\\memdump_%X_%zx_%zx.bin", getParentPath(path), DbgGetProcessId(), mem_addr, mem_size);

        // Dump payload to disk
        if (DumpMemory(DbgGetProcessHandle(), (LPVOID)mem_addr, mem_size, path))
            _plugin_logprintf("[" PLUGIN_NAME "] Dumped payload at %s\n", path);
        else
            fail("Failed to dump the payload");
    }
}
```

When we hit `VirtualProtect` we can read the first 2 bytes from the allocated memory address to check for the MZ header.

To build a dumping path similar to `:memdump:` from `savedata` command we need to get the current module path using `GetMainModulePath`, get the current process ID using `DbgGetProcessId` and append the memory address and size to them.

Finally to dump the payload to disk we can use `DumpMemory` passing it the current process handle using `DbgGetProcessHandle`, memory address, memory size and file path.

## Trying our plugin

After building the plugin we need to move the plugin files which end with `.dp32` or `.dp64` depending on the build configuration to `x64dbg\release\(x32|x64)\plugins`.

To load the the plugin we can restart x64dbg and it will be loaded automatically or just use `loadplugin` command passing it the plugin name like this `loadplugin EasyDump`.

Finally we can run `EasyDump` (the command we registered in `pluginInit`) and watch the magic happen...again.

[![2](/assets/images/tutorials/x64dbg/plugins/2.png)](/assets/images/tutorials/x64dbg/plugins/2.png)

source code: [https://github.com/N1ght-W0lf/EasyDump](https://github.com/N1ght-W0lf/EasyDump)

### Updates

> **Some notes from [Duncan Ogilvie @mrexodia](https://twitter.com/mrexodia)**
>
> As a general rule I’d avoid using the TitanEngine APIs directly. They can cause some weird scenarios where x64dbg doesn’t know about a breakpoint for example. Unfortunately the plugin API isn’t very strong on this front though, so it’s a lot more work to do the same…
>
> Also something worth exploring is the C# scripting plugin: [https://github.com/x64dbg/DotX64Dbg](https://github.com/x64dbg/DotX64Dbg) 
>
> And confusingly `DbgCmdExec` (queues a command asynchronously) causes a race condition in your example. Likely you want `DbgCmdExecDirect` instead (executed the implementation of the command directly)

## Final words

The goal of this tutorial was to learn more about x64dbg not write the best dumping plugin :)

This tutorial wouldn't be possible without the help of the official x64dbg [docs](https://help.x64dbg.com/) and [blog](https://x64dbg.com/blog/), you can check them out for more in depth info.

You can also find many cool x64dbg plugins [here](https://github.com/x64dbg/x64dbg/wiki/Plugins) that can make your life easier.

Special thanks to [@mrexodia](https://twitter.com/mrexodia) (creator of x64dbg and many other projects) for his awesome work, you can support him [here](https://github.com/sponsors/mrexodia).

I hope you learned something new, until next time.
