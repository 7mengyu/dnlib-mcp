# Reverse Tools MCP Server

MCP Server for reverse engineering tools integration with AI coding assistants.

## Supported Tools

- **dnlib Backend**: Static analysis of .NET assemblies
- **x64dbg Backend**: (Planned) Debugger automation
- **Cheat Engine Backend**: (Planned) Memory scanning

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/7mengyu/nixiang_mcp.git
cd nixiang_mcp
```

### 2. Create virtual environment and install dependencies

```bash
python -m venv venv
# Windows
venv\Scripts\pip install -r requirements.txt
# Linux/macOS
./venv/bin/pip install -r requirements.txt
```

### 3. Download dnlib.dll

**Important**: Place `dnlib.dll` in the project root directory. The system will automatically detect and load it.

**Method 1: Using curl (Recommended)**

```bash
# Windows (PowerShell/CMD)
curl -L -o dnlib.nupkg "https://www.nuget.org/api/v2/package/dnlib"
unzip -o dnlib.nupkg -d dnlib-temp
cp dnlib-temp/lib/net45/dnlib.dll .
rm -rf dnlib-temp dnlib.nupkg

# Linux/macOS
curl -L -o dnlib.nupkg "https://www.nuget.org/api/v2/package/dnlib"
unzip -o dnlib.nupkg -d dnlib-temp
cp dnlib-temp/lib/net45/dnlib.dll .
rm -rf dnlib-temp dnlib.nupkg
```

**Method 2: Manual download**

1. Visit https://www.nuget.org/packages/dnlib
2. Click "Download package"
3. Rename `.nupkg` to `.zip`
4. Extract and copy `lib/net45/dnlib.dll` to project root

**Method 3: From GitHub releases**

1. Visit https://github.com/0xd4d/dnlib/releases
2. Download the latest release zip
3. Find and extract `dnlib.dll`

## Configuration

This project uses `.mcp.json` for automatic MCP server registration. No manual configuration is needed.

Simply start Claude Code in the project directory:

```bash
cd nixiang_mcp
claude
```

Claude Code will detect `.mcp.json` and prompt you to approve the `reverse-tools` server on first launch. Run `/mcp` to check status or approve.

## Usage

### Auto-Initialization

The system automatically detects `dnlib.dll` in the following locations (in order of priority):

1. `DNLIB_PATH` environment variable
2. Project root directory (`dnlib.dll` in the same folder as this README)
3. Current working directory

If `dnlib.dll` is in the project root, no manual initialization is needed.

### Available Tools

| Tool | Description |
|------|-------------|
| `dnlib_status` | Check initialization status and current dnlib.dll path |
| `dnlib_set_path` | Manually set dnlib.dll path (optional if dll is in project root) |
| `dnlib_load_assembly` | Load a .NET assembly (.dll/.exe) |
| `dnlib_list_types` | List all types in assembly |
| `dnlib_get_type` | Get type details (methods, fields, properties) |
| `dnlib_search_types` | Search types by name pattern |
| `dnlib_search_methods` | Search methods by name pattern |
| `dnlib_decompile_method` | Decompile method to IL code |
| `dnlib_get_entry_point` | Get assembly entry point (Main) |
| `dnlib_list_resources` | List embedded resources |

### Quick Start

If `dnlib.dll` is in the project root, you can start directly:

```
加载程序集 D:\Games\SomeGame\Game.exe
```

To check initialization status:

```
检查 dnlib 状态
```

### Step-by-Step Usage Guide

#### Step 1: Check Status (Optional)

Verify dnlib is properly initialized:

```
检查 dnlib 状态
```

Or use the tool directly to see the current path and initialization state.

#### Step 2: Load Target Assembly

Load the .NET assembly you want to analyze:

```
加载程序集 D:\Games\SomeGame\Game.exe
```

The tool will return assembly info including name, version, and modules.

#### Step 3: Explore Types

List all types in the assembly:

```
列出所有类型
```

Or search for specific types:

```
搜索包含 "Player" 的类型
```

#### Step 4: Analyze a Class

Get detailed information about a specific class:

```
查看 PlayerManager 类的详细信息
```

This returns:
- Class name, namespace, base type
- Interfaces implemented
- All methods with signatures
- All fields with types
- All properties

#### Step 5: Decompile Methods

Decompile a method to IL code for detailed analysis:

```
反编译 PlayerManager.UpdatePlayer 方法
```

The output is IL assembly code showing the method's implementation.

#### Step 6: Find Entry Point

Locate the Main method:

```
获取程序入口点
```

### Complete Example Conversation

```
User: 检查 dnlib 状态

AI: [Calls dnlib_status tool]
{
  "initialized": true,
  "dnlib_path": "C:\\path\\to\\nixiang_mcp\\dnlib.dll",
  "message": "dnlib is ready"
}

User: 加载程序集 D:\Games\MyGame\MyGame.exe

AI: [Calls dnlib_load_assembly tool]
{
  "name": "MyGame",
  "full_name": "MyGame, Version=1.0.0.0",
  "version": "1.0.0.0",
  "modules": ["MyGame.exe"]
}

User: 搜索包含 "Health" 的类型

AI: [Calls dnlib_search_types tool]
[
  "MyGame.PlayerHealth",
  "MyGame.HealthSystem",
  "MyGame.UI.HealthBar"
]

User: 查看 MyGame.PlayerHealth 类的详细信息

AI: [Calls dnlib_get_type tool]
{
  "name": "PlayerHealth",
  "full_name": "MyGame.PlayerHealth",
  "namespace": "MyGame",
  "base_type": "System.Object",
  "methods": [
    {"name": "GetHealth", "return_type": "System.Int32", "is_static": false},
    {"name": "SetHealth", "return_type": "System.Void", "is_static": false},
    {"name": "TakeDamage", "return_type": "System.Void", "is_static": false}
  ],
  "fields": [
    {"name": "currentHealth", "type": "System.Int32", "is_static": false},
    {"name": "maxHealth", "type": "System.Int32", "is_static": false}
  ]
}

User: 反编译 PlayerHealth.SetHealth 方法

AI: [Calls dnlib_decompile_method tool]
; Method: System.Void MyGame.PlayerHealth.SetHealth(System.Int32)
; Token: 0x06000102

IL_0000: ldarg.0
IL_0001: ldarg.1
IL_0002: stfld System.Int32 MyGame.PlayerHealth::currentHealth
IL_0007: ret
```

### Tips for Game Reverse Engineering

#### Finding Save Encryption Keys (Mono/Unity)

Typical workflow for extracting encryption keys from `Assembly-CSharp.dll`:

**1. Load and search for save-related types:**
```
加载程序集 D:\Game\MyGame_Data\Managed\Assembly-CSharp.dll
搜索包含 "Save" 的类型
搜索包含 "Encrypt" 的类型
搜索包含 "Crypto" 的类型
```

**2. Inspect suspected classes for hardcoded keys:**
```
查看 SaveManager 类的详细信息
```

Static fields often contain hardcoded keys or IV values. Pay attention to:
- `static` fields of type `System.String` or `System.Byte[]`
- Fields named `KEY`, `IV`, `SALT`, `SECRET`, `PASSWORD`

**3. Decompile encryption methods to understand the algorithm:**
```
反编译 SaveManager.EncryptData 方法
反编译 SaveManager.DecryptData 方法
```

**4. If keys are derived, trace the derivation logic by decompiling helper methods.**

#### Common Search Keywords

| Direction | Keywords |
|-----------|----------|
| Save/Load | Save, Load, Data, Progress, Slot, File |
| Encryption | Encrypt, Decrypt, Crypto, AES, XOR, Cipher, Rijndael |
| Serialization | Serialize, Deserialize, Json, Binary, Base64, Formatter |
| Keys/Secrets | Key, IV, Salt, Secret, Password, Token, Hash |
| Storage | Path, File, PersistentData, Application, SaveData |

#### General Tips

1. **Find key classes**: Search for terms like "Player", "Health", "Money", "Inventory", "Weapon"
2. **Locate modifying methods**: Look for "Add", "Set", "Update", "Increase" method names
3. **Analyze IL code**: Simple methods like `SetHealth(value)` are easy to understand in IL
4. **Find entry points**: Entry point helps understand game initialization flow
5. **Use with other tools**: Combine with dnSpy for visual decompilation, then use MCP for quick searches

## Requirements

- Python 3.10+
- .NET Runtime (for dnlib backend via pythonnet)
- Windows OS (for pythonnet CLR interop)