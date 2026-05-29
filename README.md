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

**Method 1: Using curl (Recommended)**

```bash
# Windows (PowerShell/CMD)
curl -L -o dnlib.nupkg "https://www.nuget.org/api/v2/package/dnlib"
# Extract (requires unzip)
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

Add to your Claude Code settings (`~/.claude/settings.json`):

```json
{
  "mcpServers": {
    "reverse-tools": {
      "command": "C:\\path\\to\\nixiang_mcp\\venv\\Scripts\\python",
      "args": ["-m", "src.server"],
      "cwd": "C:\\path\\to\\nixiang_mcp"
    }
  }
}
```

## Usage

After configuration, restart Claude Code. The following tools will be available:

### dnlib Tools

| Tool | Description |
|------|-------------|
| `dnlib_set_path` | Initialize dnlib with path to dnlib.dll (must call first) |
| `dnlib_load_assembly` | Load a .NET assembly (.dll/.exe) |
| `dnlib_list_types` | List all types in assembly |
| `dnlib_get_type` | Get type details (methods, fields, properties) |
| `dnlib_search_types` | Search types by name pattern |
| `dnlib_search_methods` | Search methods by name pattern |
| `dnlib_decompile_method` | Decompile method to IL code |
| `dnlib_get_entry_point` | Get assembly entry point (Main) |
| `dnlib_list_resources` | List embedded resources |

### Example Usage

```
1. Initialize dnlib with path: C:\path\to\dnlib.dll
2. Load assembly: D:\Games\SomeGame\Game.exe
3. Search for types containing "Player"
4. Get details of PlayerClass
5. Decompile PlayerClass.Update method
```

## Requirements

- Python 3.10+
- .NET Runtime (for dnlib backend via pythonnet)
- Windows OS (for pythonnet CLR interop)