# dnlib MCP Server

基于 dnlib 和 de4dot 的 .NET 程序集分析 MCP 服务器，与 AI 编程助手集成。

## 支持的工具

- **dnlib 后端**: .NET 程序集静态分析（类型搜索、方法反编译、IL 分析）
- **de4dot 后端**: .NET 解混淆器集成（检测 + 清理混淆程序集）

## 安装

### 1. 克隆仓库

```bash
git clone https://github.com/7mengyu/dnlib-mcp.git
cd dnlib-mcp
```

### 2. 一键安装

```bash
# Windows: 双击 setup.bat，或在命令行运行：
setup.bat
```

脚本会自动：
- 创建 Python 虚拟环境
- 安装依赖（mcp、pythonnet）

### 3. （可选）编译 de4dot

`de4dot/` 目录已包含编译好的 de4dot.exe 及依赖。如需重新编译：

```bash
git clone https://github.com/0xd4d/de4dot.git
cd de4dot
dotnet build de4dot.netframework.sln -c Release
# 将编译产物复制到 dnlib-mcp/de4dot/
cp Release/net45/de4dot.exe ../dnlib-mcp/de4dot/
cp Release/net45/de4dot.code.dll ../dnlib-mcp/de4dot/
cp Release/net45/de4dot.blocks.dll ../dnlib-mcp/de4dot/
cp Release/net45/de4dot.cui.dll ../dnlib-mcp/de4dot/
cp Release/net45/de4dot.mdecrypt.dll ../dnlib-mcp/de4dot/
cp Release/net45/AssemblyData.dll ../dnlib-mcp/de4dot/
cp Release/net45/dnlib.dll ../dnlib-mcp/de4dot/
```

> **注意**: de4dot.code 的 net35 目标编译会报 `ResGen.exe not supported` 错误，不影响使用，net45 正常编译即可。

## 配置

项目使用 `.mcp.json` 自动注册 MCP 服务器，无需手动配置。

在项目目录启动 Claude Code 即可：

```bash
cd dnlib-mcp
claude
```

Claude Code 会自动检测 `.mcp.json`，首次启动时会提示批准 `reverse-tools` 服务器。运行 `/mcp` 查看状态或批准。

## 使用

### 自动初始化

系统按以下优先级自动检测资源：

**dnlib.dll：**
1. `DNLIB_PATH` 环境变量
2. 项目根目录（与 README 同级的 dnlib.dll）
3. 当前工作目录

**de4dot.exe：**
1. `DE4DOT_PATH` 环境变量
2. 项目根目录下的 `de4dot/de4dot.exe`
3. 项目根目录下的 `de4dot.exe`

### 可用工具

#### dnlib 工具

| 工具 | 说明 |
|------|------|
| `dnlib_status` | 检查初始化状态 |
| `dnlib_set_path` | 手动设置 dnlib.dll 路径（通常不需要） |
| `dnlib_load_assembly` | 加载 .NET 程序集（.dll/.exe） |
| `dnlib_list_types` | 列出程序集中所有类型 |
| `dnlib_get_type` | 获取类型详情（方法、字段、属性） |
| `dnlib_search_types` | 按名称搜索类型 |
| `dnlib_search_methods` | 按名称搜索方法 |
| `dnlib_decompile_method` | 反编译方法为 IL 代码 |
| `dnlib_get_entry_point` | 获取程序入口点（Main 方法） |
| `dnlib_list_resources` | 列出嵌入资源 |

#### de4dot 工具

| 工具 | 说明 |
|------|------|
| `de4dot_status` | 检查 de4dot 初始化状态 |
| `de4dot_set_path` | 手动设置 de4dot.exe 路径（通常不需要） |
| `de4dot_detect` | 检测混淆器类型（-d 模式，不改动文件） |
| `de4dot_list_obfuscators` | 列出所有支持的混淆器类型 |
| `de4dot_deobfuscate` | 解混淆程序集，输出清理后的文件 |
| `de4dot_clean_strings` | 仅解密字符串，保留结构不变 |

### 快速开始

```
加载程序集 D:\Games\SomeGame\Assembly-CSharp.dll
```

检查初始化状态：

```
检查 dnlib 状态
检查 de4dot 状态
```

### 混淆处理流程

```
# 1. 检查程序集是否被混淆
检测 D:\Game\Assembly-CSharp.dll 的混淆

# 2. 如果被混淆，先解混淆
解混淆 D:\Game\Assembly-CSharp.dll

# 3. 加载清理后的版本进行分析
加载程序集 D:\Game\Assembly-CSharp-cleaned.dll

# 4. 正常分析
搜索包含 "Save" 的类型
```

### 游戏逆向技巧

#### 查找存档加密密钥（Mono/Unity）

从 `Assembly-CSharp.dll` 中提取加密密钥的典型流程：

**1. 加载并搜索存档相关类型：**
```
加载程序集 D:\Game\MyGame_Data\Managed\Assembly-CSharp.dll
搜索包含 "Save" 的类型
搜索包含 "Encrypt" 的类型
搜索包含 "Crypto" 的类型
```

**2. 检查可疑类中是否有硬编码密钥：**
```
查看 SaveManager 类的详细信息
```

静态字段中常包含硬编码的密钥或 IV 值，重点关注：
- 类型为 `System.String` 或 `System.Byte[]` 的静态字段
- 名为 `KEY`、`IV`、`SALT`、`SECRET`、`PASSWORD` 的字段

**3. 反编译加密方法理解算法逻辑：**
```
反编译 SaveManager.EncryptData 方法
反编译 SaveManager.DecryptData 方法
```

**4. 如果密钥是派生出来的，通过反编译辅助方法追查派生逻辑。**

#### 常用搜索关键词

| 方向 | 关键词 |
|------|--------|
| 存档/读取 | Save, Load, Data, Progress, Slot, File |
| 加密 | Encrypt, Decrypt, Crypto, AES, XOR, Cipher, Rijndael |
| 序列化 | Serialize, Deserialize, Json, Binary, Base64, Formatter |
| 密钥/机密 | Key, IV, Salt, Secret, Password, Token, Hash |
| 存储路径 | Path, File, PersistentData, Application, SaveData |

#### 通用技巧

1. **找核心类**：搜索 "Player"、"Health"、"Money"、"Inventory"、"Weapon" 等关键词
2. **定位修改方法**：关注 "Add"、"Set"、"Update"、"Increase" 等前缀方法
3. **分析 IL 代码**：简单的赋值方法（如 `SetHealth(value)`）IL 代码很短，容易理解
4. **从入口点入手**：入口点帮助理解游戏初始化流程
5. **工具配合**：配合 dnSpy 做可视化反编译，用 MCP 做快速搜索

## 环境要求

- Python 3.10+
- .NET 运行时（pythonnet 调用 dnlib 需要）
- Windows 系统（pythonnet 的 CLR 互操作需要）