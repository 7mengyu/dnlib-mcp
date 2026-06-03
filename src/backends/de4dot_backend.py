"""de4dot backend - .NET deobfuscator integration via subprocess."""

import subprocess
import json
import os
import re
from pathlib import Path
from typing import Optional
from dataclasses import dataclass


def _find_de4dot_exe() -> Optional[str]:
    """自动查找de4dot.exe路径"""
    # 优先级：环境变量 > 项目目录 > 已知路径

    env_path = os.environ.get("DE4DOT_PATH")
    if env_path and Path(env_path).exists():
        return env_path

    # 项目根目录的 de4dot/ 子目录（优先）
    project_root = Path(__file__).parent.parent.parent
    candidates = [
        project_root / "de4dot" / "de4dot.exe",
        project_root / "de4dot.exe",
        project_root.parent / "de4dot" / "Release" / "net45" / "de4dot.exe",
    ]

    for c in candidates:
        if c.exists():
            return str(c)

    return None


DE4DOT_PATH: Optional[str] = _find_de4dot_exe()


def set_de4dot_path(path: str) -> None:
    """设置de4dot.exe的路径"""
    global DE4DOT_PATH
    DE4DOT_PATH = path


@dataclass
class DeobfuscateResult:
    """解混淆结果"""
    success: bool
    output_path: str = ""
    obfuscator: str = ""
    errors: list[str] = None
    stdout: str = ""
    stderr: str = ""

    def __post_init__(self):
        if self.errors is None:
            self.errors = []


class De4dotBackend:
    """de4dot后端，通过子进程调用de4dot.exe"""

    def __init__(self, exe_path: Optional[str] = None):
        if exe_path:
            set_de4dot_path(exe_path)
        if not DE4DOT_PATH or not Path(DE4DOT_PATH).exists():
            raise FileNotFoundError(
                "de4dot.exe not found. Please either:\n"
                "1. Place de4dot.exe in the project root, or\n"
                "2. Set DE4DOT_PATH environment variable, or\n"
                "3. Call de4dot_set_path tool with the exe path"
            )
        self._exe_path = DE4DOT_PATH

    def _run(self, args: list[str], timeout: int = 120) -> tuple[str, str, int]:
        """运行de4dot并返回(stdout, stderr, returncode)"""
        cmd = [self._exe_path] + args
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(Path(self._exe_path).parent)
        )
        return result.stdout, result.stderr, result.returncode

    def version(self) -> str:
        """获取de4dot版本"""
        stdout, _, _ = self._run(["--help"])
        match = re.search(r"de4dot v(\S+)", stdout)
        return match.group(1) if match else "unknown"

    def detect(self, path: str) -> dict:
        """检测程序集的混淆器类型（-d 模式）"""
        if not Path(path).exists():
            return {"error": f"File not found: {path}"}

        stdout, stderr, code = self._run([path, "-d"], timeout=30)

        result = {
            "file": path,
            "exit_code": code,
            "stdout": stdout.strip(),
            "obfuscators": []
        }

        # 从输出中提取检测到的混淆器
        for line in stdout.split("\n"):
            line = line.strip()
            if "Detected" in line:
                result["obfuscators"].append(line)
            elif "is obfuscated by" in line.lower():
                result["obfuscators"].append(line)
            elif "Clean" in line and "not obfuscated" in line.lower():
                result["obfuscators"].append("Not obfuscated (clean)")

        return result

    def list_obfuscators(self) -> list[str]:
        """列出所有支持的混淆器"""
        stdout, _, _ = self._run(["--help"])
        obfuscators = []
        in_section = False

        for line in stdout.split("\n"):
            if "---" in line:
                in_section = False
            if "Formal obfuscator type names" in line:
                in_section = True
                continue
            if in_section and ":" in line and "(" in line:
                name = line.strip()
                if name:
                    obfuscators.append(name)

        return obfuscators

    def deobfuscate(self, path: str, output: Optional[str] = None,
                    obfuscator_type: Optional[str] = None,
                    rename: bool = True) -> DeobfuscateResult:
        """对程序集执行解混淆"""
        if not Path(path).exists():
            return DeobfuscateResult(
                success=False,
                errors=[f"File not found: {path}"]
            )

        # 自动生成输出路径
        if not output:
            src = Path(path)
            output = str(src.parent / f"{src.stem}-cleaned{src.suffix}")

        args = [path, "-o", output]

        if not rename:
            args.append("--dont-rename")

        if obfuscator_type:
            args.extend(["-p", obfuscator_type])

        stdout, stderr, code = self._run(args)

        result = DeobfuscateResult(
            success=code == 0 and Path(output).exists(),
            output_path=output if Path(output).exists() else "",
            errors=[],
            stdout=stdout.strip(),
            stderr=stderr.strip()
        )

        # 从输出中提取信息
        for line in stdout.split("\n"):
            if "Detected" in line:
                result.obfuscator = line.strip()
            elif "ERROR" in line.upper():
                result.errors.append(line.strip())

        return result

    def clean_strings(self, path: str, str_type: str = "default",
                      output: Optional[str] = None) -> DeobfuscateResult:
        """仅解密字符串（不解混淆结构）"""
        if not output:
            src = Path(path)
            output = str(src.parent / f"{src.stem}-strdec{src.suffix}")

        args = [path, "-o", output, "--dont-rename", "--no-cflow-deob"]
        if str_type:
            args.extend(["--default-strtyp", str_type])

        stdout, stderr, code = self._run(args)

        return DeobfuscateResult(
            success=code == 0 and Path(output).exists(),
            output_path=output if Path(output).exists() else "",
            stdout=stdout.strip(),
            stderr=stderr.strip()
        )
