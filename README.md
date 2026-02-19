# TextHook_Driver

Driver that hooks an export in a legit driver for communication with the usermode

## How to build

you need:

[Windows Driver Kit](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)

[Visual Studio](https://visualstudio.microsoft.com/pl/downloads/)

Build the project in release configuration and use a manual mapper like [KDMapper](https://github.com/TheCruZ/kdmapper) or modify it to be launched via Windows SC manager.

## Docs

This driver hooks and export in dxgkrnl.sys driver for the communication with usermode, since manually mapped drivers do not have a driver object created and creating one during runtime is easily detected we need to use trickery like this.

When setup, it provides functionality for:
- **Reading usermode process's memory**
- **Writing usermode process's memory**
- **Getting usermode process's main module's base address**
- **Getting usermode process's main module's size**
