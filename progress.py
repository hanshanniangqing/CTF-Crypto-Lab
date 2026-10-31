# -*- coding: utf-8 -*-
"""
progress.py — 做题进度与 flag 判题 (CLI 与题目站共用)

核心约定：**只有提交正确的 flag 才会把本题记为完成**。
进度保存在 WLAB/progress.json，`python ctf.py submit` 与题目站
`POST /api/submit/<name>` 读写同一份记录，两边进度永远一致。

记录结构::

    {"version": 1,
     "records": {"<题目>": {"attempts": 3, "solved": true,
                            "solved_at": "2026-10-31 13:20:01",
                            "points": 100, "peeked": false}}}

`peeked` 表示交卷前看过标准答案：仍算完成，但在进度里单独标记，
方便区分「自己解出来的」和「看了答案才凑出来的」。
"""
import hmac
import json
import os
import threading
import time

import labenv

LAB = labenv.LAB
WLAB = labenv.WLAB
PROGRESS_PATH = WLAB / "progress.json"
VERSION = 1

_lock = threading.RLock()

# 中文输入法下极易打出全角括号，判题前统一归一成半角
_FULLWIDTH = str.maketrans({
    "｛": "{", "｝": "}", "（": "(", "）": ")", "＿": "_",
    "－": "-", "＝": "=", "＋": "+", "　": " ", "：": ":", "；": ";",
})

FLAG_PREFIX = "flag{"


# ------------------------------------------------------------------ 判题
def normalize(raw) -> str:
    """把用户输入整理成可比对的字符串 (去空白 / 全角归一 / 去包裹的反引号引号)"""
    s = str(raw or "")
    s = s.replace("\ufeff", "").replace("\u200b", "")
    s = s.translate(_FULLWIDTH)
    s = s.strip().strip("`'\"“”‘’").strip()
    return s


def matches(raw, expected) -> bool:
    """常数时间比较，避免逐字符短路"""
    got = normalize(raw)
    if not got:
        return False
    return hmac.compare_digest(got.encode("utf-8"),
                               str(expected or "").encode("utf-8"))


def judge_format(raw):
    """只看形状不看内容：返回 (ok, 给用户的提示)"""
    s = normalize(raw)
    if not s:
        return False, "请输入 flag"
    if not s.startswith(FLAG_PREFIX):
        return False, "flag 格式应为 flag{...}（小写 flag，半角花括号）"
    if not s.endswith("}"):
        return False, "flag 缺少结尾的 }"
    return True, ""


# ------------------------------------------------------------------ 存储
def _empty() -> dict:
    return {"version": VERSION, "records": {}}


def load() -> dict:
    with _lock:
        try:
            data = json.loads(PROGRESS_PATH.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return _empty()
        if not isinstance(data, dict) or not isinstance(data.get("records"), dict):
            return _empty()
        data.setdefault("version", VERSION)
        return data


def _save(data: dict) -> None:
    PROGRESS_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = PROGRESS_PATH.with_name("progress.json.tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n",
                   encoding="utf-8")
    os.replace(tmp, PROGRESS_PATH)


def reset() -> None:
    with _lock:
        try:
            PROGRESS_PATH.unlink()
        except FileNotFoundError:
            pass


def record(name: str) -> dict:
    """单题记录 (无记录时返回空 dict，不要写入)"""
    return load()["records"].get(name) or {}


def is_solved(name: str) -> bool:
    return bool(record(name).get("solved"))


# ------------------------------------------------------------------ 提交
def submit(challenge: dict, raw) -> dict:
    """
    提交 flag 并落盘。challenge 是 index.json 里的一道题。

    返回::

        {name, correct, reason, points, awarded, first, already,
         attempts, solved, peeked, message}
    """
    name = challenge["name"]
    expected = challenge.get("flag") or ""
    got = normalize(raw)
    ok_format, fmt_msg = judge_format(got)

    with _lock:
        data = load()
        rec = data["records"].setdefault(name, {"attempts": 0, "solved": False})
        rec["attempts"] = int(rec.get("attempts") or 0) + 1
        rec["last_at"] = time.strftime("%Y-%m-%d %H:%M:%S")

        already = bool(rec.get("solved"))
        correct = bool(got) and hmac.compare_digest(
            got.encode("utf-8"), str(expected).encode("utf-8"))

        awarded = 0
        if correct:
            if not already:
                awarded = int(challenge.get("points") or 0)
            rec["solved"] = True
            rec["points"] = int(challenge.get("points") or 0)
            rec.setdefault("solved_at", time.strftime("%Y-%m-%d %H:%M:%S"))
            reason, msg = "ok", "flag 正确"
        elif not ok_format:
            reason, msg = "format", fmt_msg
        else:
            reason, msg = "wrong", "flag 不正确，再试试"

        _save(data)
        return {
            "name": name, "correct": correct, "reason": reason, "message": msg,
            "points": int(challenge.get("points") or 0), "awarded": awarded,
            "first": correct and not already, "already": already,
            "attempts": rec["attempts"], "solved": bool(rec.get("solved")),
            "peeked": bool(rec.get("peeked")),
        }


def peek(challenge: dict) -> dict:
    """记录「看了答案」并返回 flag。不记完成，只打标记。"""
    name = challenge["name"]
    with _lock:
        data = load()
        rec = data["records"].setdefault(
            name, {"attempts": 0, "solved": False})
        rec["peeked"] = True
        rec["peeked_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        _save(data)
        return {"name": name, "flag": challenge.get("flag"),
                "solved": bool(rec.get("solved")), "peeked": True}


# ------------------------------------------------------------------ 汇总
def stats(index: dict) -> dict:
    """index 为 {name: challenge}，返回全局统计"""
    data = load()
    recs = data["records"]
    total_pts = sum(int(c.get("points") or 0) for c in index.values())

    solved = [n for n, r in recs.items()
              if r.get("solved") and n in index]
    clean = [n for n in solved if not recs[n].get("peeked")]
    peeked_only = [n for n in solved if recs[n].get("peeked")]
    pts = sum(int(index[n].get("points") or 0) for n in solved)
    clean_pts = sum(int(index[n].get("points") or 0) for n in clean)

    return {
        "total": len(index), "total_points": total_pts,
        "solved": len(solved), "solved_points": pts,
        "clean": len(clean), "clean_points": clean_pts,
        "peeked": len(peeked_only),
        "attempts": sum(int(r.get("attempts") or 0) for r in recs.values()),
        "percent": round(pts * 100.0 / total_pts, 1) if total_pts else 0.0,
    }


def summary(index: dict) -> dict:
    """给 Web 前端的完整快照"""
    return {"records": load()["records"], "stats": stats(index)}


def by_category(index: dict, order=None) -> list:
    """按分类聚合完成情况，供 `ctf.py progress` 使用"""
    data = load()
    recs = data["records"]
    cats = {}
    for name, c in index.items():
        cat = c.get("category", "other")
        row = cats.setdefault(cat, {"total": 0, "solved": 0,
                                    "points": 0, "solved_points": 0})
        row["total"] += 1
        row["points"] += int(c.get("points") or 0)
        if recs.get(name, {}).get("solved"):
            row["solved"] += 1
            row["solved_points"] += int(c.get("points") or 0)
    keys = [k for k in (order or []) if k in cats] + \
           [k for k in cats if k not in (order or [])]
    return [{"category": k, **cats[k]} for k in keys]
