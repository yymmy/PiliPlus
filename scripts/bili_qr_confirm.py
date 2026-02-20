#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""使用已保存的 bili_credentials.json 完成扫码确认。

说明：
- 不修改原有短信登录脚本。
- 读取已有凭证（主要用 cookies + bili_jct）调用:
  https://passport.bilibili.com/x/passport-tv-login/h5/qrcode/confirm
- 你只需要传入二维码解码后的链接（或直接 auth_code）。
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import requests

QRCODE_CONFIRM_API = "https://passport.bilibili.com/x/passport-tv-login/h5/qrcode/confirm"
WEB_QRCODE_CONFIRM_API = "https://passport.bilibili.com/x/passport-login/h5/qrcode/confirm"
DEFAULT_CRED_FILE = "bili_credentials.json"


class ConfirmError(RuntimeError):
    pass


def parse_json_or_raise(resp: requests.Response, api_name: str) -> dict[str, Any]:
    try:
        return resp.json()
    except Exception:
        content_type = resp.headers.get("content-type", "")
        body_preview = resp.text[:400].replace("\n", "\\n")
        raise ConfirmError(
            f"{api_name} 返回非 JSON: HTTP {resp.status_code}, "
            f"Content-Type={content_type}, Body前400={body_preview}"
        )


def load_credentials(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise ConfirmError(f"凭证文件不存在: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ConfirmError(f"凭证文件格式错误(非对象): {path}")
    return data


def extract_auth_code(qr_url_or_code: str) -> str:
    raw = qr_url_or_code.strip()
    if not raw:
        raise ConfirmError("二维码链接/认证码不能为空")

    # 直接传 auth_code
    if not raw.startswith(("http://", "https://")):
        return raw

    parsed = urlparse(raw)
    query = parse_qs(parsed.query)

    # 尽量兼容常见字段
    for key in ("auth_code", "authCode", "code"):
        val = (query.get(key) or [""])[0].strip()
        if val:
            return val

    raise ConfirmError("未在链接 query 中找到 auth_code/authCode/code")


def extract_qrcode_key(qr_url: str) -> str:
    parsed = urlparse(qr_url.strip())
    query = parse_qs(parsed.query)
    qrcode_key = (query.get("qrcode_key") or [""])[0].strip()
    if not qrcode_key:
        raise ConfirmError("未在链接 query 中找到 qrcode_key")
    return qrcode_key


def build_session_from_credentials(cred: dict[str, Any]) -> tuple[requests.Session, str]:
    cookies = cred.get("cookies") or {}
    if not isinstance(cookies, dict) or not cookies:
        raise ConfirmError("凭证中缺少 cookies")

    csrf = cookies.get("bili_jct")
    if not csrf:
        raise ConfirmError("凭证 cookies 中缺少 bili_jct（csrf）")

    sess = requests.Session()
    sess.headers.update(
        {
            "User-Agent": (
                "Mozilla/5.0 BiliDroid/2.0.1 (bbcallen@gmail.com) os/android "
                "model/android_hd mobi_app/android_hd build/2001100 "
                "channel/master innerVer/2001100 osVer/15 network/2"
            ),
            "Accept": "application/json, text/plain, */*",
            "Referer": "https://passport.bilibili.com/",
            "Origin": "https://passport.bilibili.com",
        }
    )

    for name, value in cookies.items():
        if value is None:
            continue
        sess.cookies.set(name, str(value), domain=".bilibili.com", path="/")

    return sess, str(csrf)


def confirm_qr_login(qr_url_or_code: str, cred_file: Path, timeout: int = 20) -> dict[str, Any]:
    cred = load_credentials(cred_file)
    session, csrf = build_session_from_credentials(cred)

    raw = qr_url_or_code.strip()
    if raw.startswith(("http://", "https://")) and "qrcode_key=" in raw:
        # Web 扫码链接（如 account.bilibili.com/.../scan-web?...&qrcode_key=xxx）
        qrcode_key = extract_qrcode_key(raw)
        payload = {
            "qrcode_key": qrcode_key,
            "csrf": csrf,
            "source": "main-fe-header",
        }
        resp = session.post(WEB_QRCODE_CONFIRM_API, data=payload, timeout=timeout)
    else:
        # TV 端 auth_code 场景
        auth_code = extract_auth_code(raw)
        payload = {
            "auth_code": auth_code,
            "csrf": csrf,
            "scanning_type": "1",
        }
        resp = session.post(QRCODE_CONFIRM_API, data=payload, timeout=timeout)

    data = parse_json_or_raise(resp, "qrcodeConfirm")
    return data


def main() -> None:
    parser = argparse.ArgumentParser(description="使用保存的凭证完成 B 站二维码确认")
    parser.add_argument(
        "--qr",
        required=True,
        help="二维码解码后的链接（或直接 auth_code）",
    )
    parser.add_argument(
        "--cred",
        default=DEFAULT_CRED_FILE,
        help=f"凭证文件路径（默认: {DEFAULT_CRED_FILE}）",
    )
    parser.add_argument("--timeout", type=int, default=20, help="请求超时时间（秒）")
    args = parser.parse_args()

    result = confirm_qr_login(args.qr, Path(args.cred), args.timeout)
    print("[qrcodeConfirm]", result)

    if result.get("code") != 0:
        raise SystemExit(f"扫码确认失败: {result}")

    print("扫码确认成功")


if __name__ == "__main__":
    main()
