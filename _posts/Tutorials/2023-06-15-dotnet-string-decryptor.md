---
title: "Dotnet String Decryptor"
classes: wide
header:
  teaser: /assets/images/tutorials/dotnet/logo.png
ribbon: ForestGreen
description: "Welcome back! This is a short blog about reverse engineering dotnet malware. When working with dotnet malware samples..."
categories:
  - Tutorials
toc: true
---

Welcome back! This is a short blog post about reverse engineering dotnet malware.

When working with dotnet malware samples I always come around samples with obfuscated strings which makes analysis harder.

My go to way to handle this situation was to identify the string decryption routine (through static/dynamic analysis) then use `de4dot` to decrypt the strings.

But sometimes you don't want to go through every sample and find the decryption routine or you need to automate this process for a collection of different samples.

While looking around for a solution I found this cool [blog](http://rhotav.com/stringDecryptionWithPythonen/), so I will be building on it to write a generic dotnet string decryptor which will hopefully make life a bit easier.

We will be working on an obfuscated sample of [DCRat](https://malpedia.caad.fkie.fraunhofer.de/details/win.dcrat) to test our script.
[c6244c8e4e4cdecd641017d52d344b1db6a23d05fd6a8ad338c8f4f77481f483](https://bazaar.abuse.ch/sample/c6244c8e4e4cdecd641017d52d344b1db6a23d05fd6a8ad338c8f4f77481f483/)

# Writing the deobfuscation script

## Step 1 : Importing libs and loading the .NET file

We first need to install `pythonnet` which allows CLR namespaces to be treated essentially as python packages.

```
pip install pythonnet
```

Then we can import the required reflection modules which we will use later to get and invoke decryption methods.

```python
import clr
from System.Reflection import Assembly, BindingFlags, MethodInfo
```

We also need to add a reference to `dnlib.dll` which we will use to parse the .NET assemblies and modules.

```python
clr.AddReference("./dnlib")

import dnlib
from dnlib.DotNet import ModuleDef, ModuleDefMD
from dnlib.DotNet.Emit import OpCodes
from dnlib.DotNet.Writer import ModuleWriterOptions
```

Now we can load our .NET file.

```python
file_module = ModuleDefMD.Load(file_path)
file_assembly = Assembly.LoadFile(file_path)
```

## Step 2 : Finding suspected decryption methods

Before we get any further we need to define the signatures of the suspected methods that are used for string decryption.

A method signature consists of the type of its parameters and its return type.

Below is the string decryption method in the sample we are working on:

[![1](/assets/images/tutorials/dotnet/1.png)](/assets/images/tutorials/dotnet/1.png)

I also found some wrapper methods that call the decryption method and they had a different signature.

[![2](/assets/images/tutorials/dotnet/2.png)](/assets/images/tutorials/dotnet/2.png)

So we can define our suspected method signatures as follows:

```python
DECRYPTION_METHOD_SIGNATURES = [
    {
        "Parameters": ["System.Int32"],
        "ReturnType": "System.String"
    },
    {
        "Parameters": ["System.Int32"],
        "ReturnType": "System.Object"
    },
]
```

Of course there could be other methods with similar signatures which are not related to string decryption, but invoking them shouldn't affect the end result (**and you better run the script in a sandboxed environment**).

Next we use the reflection modules to loop through the methods of each Type (classes, interfaces, ...) and find suspected methods based on the list of signatures we defined above.

```python
# Search for static, public and non public members
eFlags = BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic

for module_type in file_assembly.GetTypes():
    for method in module_type.GetMethods(eFlags):
```

If we find a suspected method we need to store its corresponding signature and [MethodInfo](https://learn.microsoft.com/en-us/dotnet/api/system.reflection.methodinfo) object which we will use later to invoke that method.

```python
        # Check if the current method has a suspected signature
        for sig in StringDecryptor.DECRYPTION_METHOD_SIGNATURES:
            # Check number of parameters and return type
            parameters = method.GetParameters()
            if ((len(parameters) == len(sig["Parameters"])) and
                (method.ReturnType.FullName == sig["ReturnType"])):
               
                # Check parameters types
                param_types_match = True
                for i in range(len(parameters)):
                    if parameters[i].ParameterType.FullName != sig["Parameters"][i]:
                        param_types_match = False
                        break

                if param_types_match:
                    # Store the signature and MethodInfo object of the current method
                    method_name = f"{method.DeclaringType.FullName}::{method.Name}"
                    suspected_methods[method_name] = (sig, method)
```

## Step 3 : Finding references to suspected methods

The next step is to find references to the suspected methods so we can get the required parameters.

To do this we can use dnlib modules to loop through the CIL instructions of each method and find calls to these methods.

```python
for module_type in file_module.Types:
    if not module_type.HasMethods:
        continue

    for method in module_type.Methods:
        if not method.HasBody:
            continue

        # Loop through method instructions
        for insnIdx, insn in enumerate(method.Body.Instructions):
            # Find Call instructions
            if insn.OpCode == OpCodes.Call:
                for s_method_name, (s_method_sig, s_method_info) in suspected_methods.items():
                    # Check if the callee is one of the suspected methods
                    if str(s_method_name) in str(insn.Operand):
```

If we find a reference call, we need to get the required parameters (note that they are pushed to the stack in reverse order).

```python
                                # Get method parameters in reverse order
                                params = []
                                for i in range(len(s_method_sig["Parameters"])):
                                    operand = GetOperandValue(
                                        method.Body.Instructions[insnIdx - i - 1],
                                        s_method_sig["Parameters"][-i - 1])
                                    if operand is not None:
                                        params.append(operand)

                                # Check if we got all the parameters
                                if len(params) == len(s_method_sig["Parameters"]):
```

Next we can invoke suspected methods to get the decrypted strings

```python
                                    # Invoke suspected method
                                    try:
                                        result = str(s_method_info.Invoke(None, params[::-1]))
                                    except Exception as e:
                                        continue
```

## Step 4 : Patching

If the method invoke succeeded we can safely patch the method parameters with NOPs and patch the method call itself with the decrypted string.

```python
                                    # Patch suspected method parameters with NOPs
                                    for i in range(len(s_method_sig["Parameters"])):
                                        method.Body.Instructions[insnIdx - i - 1].OpCode = OpCodes.Nop

                                    # Patch suspected method call with the result string
                                    method.Body.Instructions[insnIdx].OpCode = OpCodes.Ldstr
                                    method.Body.Instructions[insnIdx].Operand = result
                                    decrypted_strings.append(result)
```

## Step 5 : Saving

Finally we can save the deobfuscated file to disk.

```python
# Add writer options to ignore dnlib errors
options = ModuleWriterOptions(file_module)
options.Logger = dnlib.DotNet.DummyLogger.NoThrowInstance

# Write cleaned module content
file_module.Write("out.bin", options)
```

# Testing and final notes

Let's run the script on the sample we have and see the results.

[![3](/assets/images/tutorials/dotnet/3.png)](/assets/images/tutorials/dotnet/3.png) | [![4](/assets/images/tutorials/dotnet/4.png)](/assets/images/tutorials/dotnet/4.png)

Perfect, now it's much easier to work on the sample and analyze its functionalities.

A little something before we wrap up, you can check if a PE is a dotnet file by checking the existence of the `IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR` data directory (at index 14).

```python
dotnet_dir = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR'] # COM descriptor table index
if pe.OPTIONAL_HEADER.DATA_DIRECTORY[dotnet_dir].VirtualAddress == 0:
    sys.exit("[-] File is not .NET")
```

The full code can be found [here](https://github.com/n1ght-w0lf/dotnet-string-decryptor).

Until next time, cheers!
