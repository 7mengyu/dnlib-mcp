# Reverse Tools MCP Server

MCP Server for reverse engineering tools integration with AI coding assistants.

## Supported Tools

- **dnlib Backend**: Static analysis of .NET assemblies
- **x64dbg Backend**: (Planned) Debugger automation
- **Cheat Engine Backend**: (Planned) Memory scanning

## Installation

```bash
pip install -e .
```

## Usage

Add to your AI client's MCP configuration:

```json
{
  "mcpServers": {
    "reverse-tools": {
      "command": "python",
      "args": ["-m", "src.server"]
    }
  }
}
```

## Requirements

- Python 3.10+
- .NET Runtime (for dnlib backend via pythonnet)