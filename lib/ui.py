# -*- coding: utf-8 -*-
"""
ui.py — 终端 UI 层 (rich 富文本, 无 rich 时自动降级为 ANSI 纯文本)

ctf.py 通过本模块输出所有内容, 保证:
  * rich 可用 → 表格/面板/进度条/彩色
  * rich 不可用 → ANSI 彩色纯文本, 功能不缩水
"""
import os
import shutil
import sys

os.environ.setdefault("FORCE_COLOR", "0")

try:
    from rich.console import Console as _RichConsole
    from rich.panel import Panel as _Panel
    from rich.table import Table as _Table
    from rich.text import Text as _Text
    from rich.progress import (Progress as _Progress, SpinnerColumn as _Spinner,
                               TextColumn as _TextCol, TimeElapsedColumn as _TimeCol)
    from rich import box as _box
    HAVE_RICH = True
except Exception:  # pragma: no cover
    HAVE_RICH = False

# ANSI 简易色 (降级用)
import re as _re

def _strip(s):
    return _re.sub(r"\[/?(?:bold|dim|red|green|yellow|cyan|white|bright_cyan|dark_orange|grey39)[^\]]*\]", "", str(s))

def _c(code, s):
    if sys.stdout.isatty():
        return f"\033[{code}m{s}\033[0m"
    return str(s)

def green(s):  return _c("32", s)
def red(s):    return _c("31", s)
def yellow(s): return _c("33", s)
def cyan(s):   return _c("36", s)
def bold(s):   return _c("1", s)
def dim(s):    return _c("2", s)

# 难度配色
DIFF_COLOR = {"入门": "green", "简单": "cyan", "中等": "yellow", "困难": "dark_orange", "专家": "red"}
STATUS_COLOR = {"PASS": "green", "FAIL": "red", "ERROR": "red", "SKIP": "dim", "TIMEOUT": "yellow"}


class UI:
    def __init__(self, force_plain=False):
        self.rich = HAVE_RICH and not force_plain
        if self.rich:
            self.console = _RichConsole(highlight=False, emoji=False)

    # ---------- 布局 ----------
    def header(self, text):
        if self.rich:
            self.console.print(f"[bold bright_cyan]{text}[/bold bright_cyan]")
        else:
            print(bold(cyan(text)))

    def rule(self, text=""):
        if self.rich:
            self.console.rule(f"[bright_cyan]{text}[/bright_cyan]")
        else:
            w = shutil.get_terminal_size((90, 24)).columns
            pad = f" {text} " if text else ""
            side = max(0, w - len(pad) - len(text) * 0)  # 中文宽度粗略忽略
            print(dim("─" * 8) + bold(cyan(pad)) + dim("─" * max(8, w - len(pad) - 16)))

    def panel(self, text, title=None, color="bright_cyan"):
        if self.rich:
            self.console.print(_Panel(text, title=title, border_style=color, padding=(0, 1)))
        else:
            print(dim("┌─" + (f" {title} " if title else "") + "─" * 30))
            for line in _strip(text).splitlines():
                print("│ " + line)
            print(dim("└" + "─" * 50))

    # ---------- 表格 ----------
    def table(self, title, headers, rows, colors=None):
        """colors: 可选, rows 同形状的样式描述 (值 -> rich 颜色映射由调用方处理)"""
        if self.rich:
            t = _Table(title=title, box=_box.SIMPLE_HEAVY, header_style="bold white",
                       border_style="grey39", pad_edge=False)
            for h in headers:
                t.add_column(h)
            for row in rows:
                cells = []
                for v in row:
                    s = str(v)
                    style = self._auto_style(s)
                    cells.append(f"[{style}]{s}[/]" if style else s)
                t.add_row(*cells)
            self.console.print(t)
        else:
            if title:
                print(bold(f"\n{title}"))
            ws = [max(len(str(h)), *(len(str(r[i])) for r in rows)) if rows else len(str(h))
                  for i, h in enumerate(headers)]
            print(dim("  " + "  ".join(str(h).ljust(w) for h, w in zip(headers, ws))))
            for r in rows:
                print("  " + "  ".join(str(v).ljust(w) for v, w in zip(r, ws)))

    @staticmethod
    def _auto_style(s):
        t = str(s)
        for k, col in STATUS_COLOR.items():
            if t == f"[{k}]" or t.startswith(k):
                return col
        for k, col in DIFF_COLOR.items():
            if t == k:
                return col
        if t in ("✓", "✗", "PASS"):
            return "green" if t != "✗" else "red"
        if t.endswith("[未生成]") or t.startswith("[未生成]"):
            return "dim"
        return None

    # ---------- 状态输出 ----------
    def ok(self, msg):   self._status("green", "✔", msg)
    def warn(self, msg): self._status("yellow", "⚠", msg)
    def err(self, msg):  self._status("red", "✘", msg)
    def info(self, msg): self._status("cyan", "•", msg)

    def _status(self, color, icon, msg):
        if self.rich:
            self.console.print(f"[{color}]{icon}[/{color}] {msg}")
        else:
            print(f"{_c({'green':32,'yellow':33,'red':31,'cyan':36}[color], icon)} {_strip(msg)}")

    # ---------- 进度 ----------
    def progress(self, total_desc=""):
        if self.rich:
            return _Progress(_Spinner(), _TextCol("{task.description}"),
                             _TimeCol(), console=self.console, transient=True)
        return _PlainProgress()

    def kv(self, key, value):
        if self.rich:
            self.console.print(f"[dim]{key:<10}[/dim][white]{value}[/white]")
        else:
            print(f"{dim(key.ljust(10))}{_strip(value)}")


class _PlainProgress:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass

    def add_task(self, desc, total=None):
        return 0

    def update(self, task_id, description=None, completed=None, total=None):
        pass

    def advance(self, task_id, n=1):
        pass
