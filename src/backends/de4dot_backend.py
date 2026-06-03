"""de4dot backend - .NET deobfuscator integration via subprocess."""

import subprocess
import json
import os
import re
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field


def _find_de4dot_exe() -> Optional[str]:
    """自动查找de4dot.exe路径"""
    env_path = os.environ.get("DE4DOT_PATH")
    if env_path and Path(env_path).exists():
        return env_path

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
    global DE4DOT_PATH
    DE4DOT_PATH = path


@dataclass
class DeobfuscateResult:
    success: bool
    output_path: str = ""
    obfuscator: str = ""
    errors: list[str] = field(default_factory=list)
    stdout: str = ""
    stderr: str = ""


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
        stdout, _, _ = self._run(["--help"])
        match = re.search(r"de4dot v(\S+)", stdout)
        return match.group(1) if match else "unknown"

    def detect(self, path: str) -> dict:
        """检测混淆器类型"""
        if not Path(path).exists():
            return {"error": f"File not found: {path}"}

        stdout, _, code = self._run([path, "-d"], timeout=30)
        result = {"file": path, "exit_code": code, "stdout": stdout.strip(), "obfuscators": []}

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
        """列出支持的混淆器"""
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
                    rename: bool = True,
                    keep_names: str = "",
                    no_cflow: bool = False,
                    only_cflow: bool = False,
                    str_type: str = "",
                    str_token: str = "",
                    keep_types: bool = False,
                    preserve_tokens: bool = False,
                    preserve_table: str = "",
                    load_new_process: bool = False,
                    ) -> DeobfuscateResult:
        """完整解混淆"""
        if not Path(path).exists():
            return DeobfuscateResult(success=False, errors=[f"File not found: {path}"])

        if not output:
            src = Path(path)
            output = str(src.parent / f"{src.stem}-cleaned{src.suffix}")

        args = [path, "-o", output]

        if obfuscator_type:
            args.extend(["-p", obfuscator_type])
        if not rename:
            args.append("--dont-rename")
        if keep_names:
            args.extend(["--keep-names", keep_names])
        if no_cflow:
            args.append("--no-cflow-deob")
        if only_cflow:
            args.append("--only-cflow-deob")
        if str_type:
            args.extend(["--default-strtyp", str_type])
        if str_token:
            args.extend(["--default-strtok", str_token])
        if keep_types:
            args.append("--keep-types")
        if preserve_tokens:
            args.append("--preserve-tokens")
        if preserve_table:
            args.extend(["--preserve-table", preserve_table])
        if load_new_process:
            args.append("--load-new-process")

        stdout, stderr, code = self._run(args)

        result = DeobfuscateResult(
            success=code == 0 and Path(output).exists(),
            output_path=output if Path(output).exists() else "",
            stdout=stdout.strip(),
            stderr=stderr.strip(),
        )

        for line in stdout.split("\n"):
            if "Detected" in line:
                result.obfuscator = line.strip()
            elif "ERROR" in line.upper():
                result.errors.append(line.strip())

        return result

    def batch_deobfuscate(self, input_dir: str, output_dir: Optional[str] = None,
                          skip_unsupported: bool = False,
                          obfuscator_type: Optional[str] = None,
                          rename: bool = True,
                          keep_names: str = "",
                          no_cflow: bool = False,
                          str_type: str = "",
                          ) -> DeobfuscateResult:
        """批量处理目录"""
        if not Path(input_dir).is_dir():
            return DeobfuscateResult(success=False, errors=[f"Directory not found: {input_dir}"])

        args = ["-r", input_dir]

        if output_dir:
            args.extend(["-ro", output_dir])
        if skip_unsupported:
            args.append("-ru")
        if obfuscator_type:
            args.extend(["-p", obfuscator_type])
        if not rename:
            args.append("--dont-rename")
        if keep_names:
            args.extend(["--keep-names", keep_names])
        if no_cflow:
            args.append("--no-cflow-deob")
        if str_type:
            args.extend(["--default-strtyp", str_type])

        stdout, stderr, code = self._run(args, timeout=300)

        return DeobfuscateResult(
            success=code == 0,
            stdout=stdout.strip(),
            stderr=stderr.strip(),
        )

    def clean_strings(self, path: str, str_type: str = "default",
                      str_token: str = "",
                      output: Optional[str] = None,
                      load_new_process: bool = False,
                      ) -> DeobfuscateResult:
        """仅解密字符串"""
        if not output:
            src = Path(path)
            output = str(src.parent / f"{src.stem}-strdec{src.suffix}")

        args = [path, "-o", output, "--dont-rename", "--no-cflow-deob"]
        if str_type:
            args.extend(["--default-strtyp", str_type])
        if str_token:
            args.extend(["--default-strtok", str_token])
        if load_new_process:
            args.append("--load-new-process")

        stdout, stderr, code = self._run(args)

        return DeobfuscateResult(
            success=code == 0 and Path(output).exists(),
            output_path=output if Path(output).exists() else "",
            stdout=stdout.strip(),
            stderr=stderr.strip(),
        )
