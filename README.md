# dnlib MCP Server

[中文文档](README_CN.md)

MCP Server for .NET assembly analysis using dnlib and de4dot, integrated with AI coding assistants.

## Supported Tools

- **dnlib Backend**: Static analysis of .NET assemblies (type search, method decompilation, IL analysis)
- **de4dot Backend**: .NET deobfuscator integration (detect + clean obfuscated assemblies)

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/7mengyu/dnlib-mcp.git
cd dnlib-mcp
```

### 2. One-click setup

```bash
# Windows: double-click setup.bat, or run:
setup.bat
```

This script will:
- Create Python virtual environment
- Install dependencies (mcp, pythonnet)

### 3. (Optional) Compile de4dot

de4dot.exe and dependencies are already included in `de4dot/`. If you need to recompile:

```bash
git clone https://github.com/0xd4d/de4dot.git
cd de4dot
dotnet build de4dot.netframework.sln -c Release
# Copy output files to dnlib-mcp/de4dot/
cp Release/net45/de4dot.exe ../dnlib-mcp/de4dot/
cp Release/net45/de4dot.code.dll ../dnlib-mcp/de4dot/
cp Release/net45/de4dot.blocks.dll ../dnlib-mcp/de4dot/
cp Release/net45/de4dot.cui.dll ../dnlib-mcp/de4dot/
cp Release/net45/de4dot.mdecrypt.dll ../dnlib-mcp/de4dot/
cp Release/net45/AssemblyData.dll ../dnlib-mcp/de4dot/
cp Release/net45/dnlib.dll ../dnlib-mcp/de4dot/
```

## Configuration

This project uses `.mcp.json` for automatic MCP server registration. No manual configuration is needed.

Simply start Claude Code in the project directory:

```bash
cd dnlib-mcp
claude
```

Claude Code will detect `.mcp.json` and prompt you to approve the `reverse-tools` server on first launch. Run `/mcp` to check status or approve.

## Usage

### Auto-Initialization

The system automatically detects resources in the following locations (in order of priority):

**dnlib.dll:**
1. `DNLIB_PATH` environment variable
2. Project root directory (`dnlib.dll` in the same folder as this README)
3. Current working directory

**de4dot.exe:**
1. `DE4DOT_PATH` environment variable
2. `de4dot/de4dot.exe` in project root
3. `de4dot.exe` in project root

### Available Tools

#### dnlib Tools

| Tool | Description |
|------|-------------|
| `dnlib_status` | Check initialization status |
| `dnlib_set_path` | Set dnlib.dll path (optional) |
| `dnlib_load_assembly` | Load a .NET assembly (.dll/.exe) |
| `dnlib_list_types` | List all types in assembly |
| `dnlib_get_type` | Get type details (methods, fields, properties) |
| `dnlib_search_types` | Search types by name pattern |
| `dnlib_search_methods` | Search methods by name pattern |
| `dnlib_decompile_method` | Decompile method to IL code |
| `dnlib_get_entry_point` | Get assembly entry point (Main) |
| `dnlib_list_resources` | List embedded resources |

#### de4dot Tools

| Tool | Description |
|------|-------------|
| `de4dot_status` | Check de4dot initialization |
| `de4dot_set_path` | Set de4dot.exe path (optional) |
| `de4dot_detect` | Detect obfuscator type (-d mode, no modification) |
| `de4dot_list_obfuscators` | List all supported obfuscator types |
| `de4dot_deobfuscate` | Deobfuscate an assembly, output cleaned file |
| `de4dot_clean_strings` | Decrypt strings only, preserve structure |

### Quick Start

```
加载程序集 D:\Games\SomeGame\Assembly-CSharp.dll
```

To check initialization:

```
检查 dnlib 状态
检查 de4dot 状态
```

### Obfuscation Handling Workflow

```
# 1. Check if the assembly is obfuscated
检测 D:\Game\Assembly-CSharp.dll 的混淆

# 2. If obfuscated, deobfuscate it
解混淆 D:\Game\Assembly-CSharp.dll

# 3. Load the cleaned version for analysis
加载程序集 D:\Game\Assembly-CSharp-cleaned.dll

# 4. Analyze as usual
搜索包含 "Save" 的类型
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