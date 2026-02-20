#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""B 站 App 短信登录 + 凭证扫码确认脚本（基于 PiliPlus 登录实现）

子命令：
1) sms-login: 发送短信并登录，保存凭证到 bili_credentials.json
2) qr-confirm: 使用已保存凭证，确认一条扫码链接（你传入二维码解码后的链接）
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import random
import string
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, quote, urlencode, urlparse

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

# 默认值与 PiliPlus/common/constants.dart 保持一致。
# 重要：通过某组 APP_KEY/APP_SEC 获取的 access_token，后续 sign 接口必须继续使用同一组。
DEFAULT_APP_KEY = "dfca71928277209b"
DEFAULT_APP_SEC = "b5475a8825547a4fc26c7d518eaaa02e"
APP_KEY = os.getenv("BILI_APP_KEY", DEFAULT_APP_KEY)
APP_SEC = os.getenv("BILI_APP_SEC", DEFAULT_APP_SEC)

PASSPORT_BASE = "https://passport.bilibili.com"
GET_WEB_KEY = f"{PASSPORT_BASE}/x/passport-login/web/key"
APP_SMS_SEND = f"{PASSPORT_BASE}/x/passport-login/sms/send"
APP_SMS_LOGIN = f"{PASSPORT_BASE}/x/passport-login/login/sms"
QRCODE_CONFIRM = f"{PASSPORT_BASE}/x/passport-tv-login/h5/qrcode/confirm"

USER_AGENT = (
    "Mozilla/5.0 BiliDroid/2.0.1 (bbcallen@gmail.com) os/android "
    "model/android_hd mobi_app/android_hd build/2001100 channel/master "
    "innerVer/2001100 osVer/15 network/2"
)
STATISTICS = '{"appId":5,"platform":3,"version":"2.0.1","abtest":""}'


@dataclass
class CaptchaInfo:
    recaptcha_token: Optional[str] = None
    gee_gt: Optional[str] = None
    gee_challenge: Optional[str] = None
    gee_validate: Optional[str] = None
    gee_seccode: Optional[str] = None


class ApiError(RuntimeError):
    pass


def ensure_key_pair_valid() -> None:
    key_set = "BILI_APP_KEY" in os.environ
    sec_set = "BILI_APP_SEC" in os.environ
    if key_set != sec_set:
        raise SystemExit("请同时设置 BILI_APP_KEY 与 BILI_APP_SEC，或都不设置使用默认值。")


def gen_buvid3() -> str:
    return f"{str(uuid.uuid4()).upper()}{random.randint(0, 99999):05d}infoc"


def _dec2bcd(num: int) -> int:
    return ((num // 10) << 4) | (num % 10)


def gen_device_id() -> str:
    now = time.localtime()
    buf = bytearray(random.getrandbits(8) for _ in range(16))
    buf.extend(
        [
            _dec2bcd((now.tm_year // 100) % 100),
            _dec2bcd(now.tm_year % 100),
            _dec2bcd(now.tm_mon),
            _dec2bcd(now.tm_mday),
            _dec2bcd(now.tm_hour),
            _dec2bcd(now.tm_min),
            _dec2bcd(now.tm_sec),
        ]
    )
    buf.extend(random.getrandbits(8) for _ in range(8))
    checksum = f"{sum(buf) & 0xFF:02x}"
    return hashlib.md5(bytes(buf)).hexdigest() + checksum


def app_sign(params: Dict[str, Any]) -> Dict[str, str]:
    data = {k: str(v) for k, v in params.items() if v is not None and v != ""}
    data["appkey"] = APP_KEY
    data["ts"] = str(int(time.time()))
    items = sorted(data.items(), key=lambda kv: kv[0])
    data["sign"] = hashlib.md5((urlencode(items) + APP_SEC).encode("utf-8")).hexdigest()
    return data


def random_str(n: int = 16) -> str:
    return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(n))


def parse_json_or_raise(resp: requests.Response, api_name: str) -> Dict[str, Any]:
    ctype = resp.headers.get("content-type", "")
    try:
        return resp.json()
    except Exception:
        snippet = resp.text[:400].replace("\n", "\\n")
        raise ApiError(
            f"{api_name} 返回非 JSON: HTTP {resp.status_code}, Content-Type={ctype}, Body前400={snippet}"
        )


def parse_recaptcha_url(url: str) -> CaptchaInfo:
    q = parse_qs(urlparse(url).query)
    return CaptchaInfo(
        recaptcha_token=(q.get("recaptcha_token") or [None])[0],
        gee_gt=(q.get("gee_gt") or [None])[0],
        gee_challenge=(q.get("gee_challenge") or [None])[0],
    )


def parse_auth_code(qr_url_or_code: str) -> str:
    raw = qr_url_or_code.strip()
    if "http://" not in raw and "https://" not in raw:
        return raw
    parsed = urlparse(raw)
    q = parse_qs(parsed.query)
    for key in ("auth_code", "authCode", "code"):
        v = (q.get(key) or [""])[0].strip()
        if v:
            return v
    raise SystemExit("二维码链接里未找到 auth_code，请确认你传入的是扫码解码后的完整链接。")


def load_saved_credentials(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise SystemExit(f"凭证文件不存在: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


class BiliClient:
    def __init__(self) -> None:
        self.buvid = gen_buvid3()
        self.device_id = gen_device_id()
        self.session = requests.Session()
        self.session.headers.update(
            {
                "user-agent": USER_AGENT,
                "accept": "application/json, text/plain, */*",
                "accept-language": "zh-CN,zh;q=0.9",
                "buvid": self.buvid,
                "env": "prod",
                "app-key": "android_hd",
                "x-bili-trace-id": "11111111111111111111111111111111:1111111111111111:0:0",
                "x-bili-aurora-eid": "",
                "x-bili-aurora-zone": "",
                "bili-http-engine": "cronet",
                "content-type": "application/x-www-form-urlencoded; charset=utf-8",
            }
        )

    def get_web_key(self) -> Dict[str, Any]:
        resp = self.session.get(GET_WEB_KEY, timeout=20)
        if resp.status_code == 200:
            data = parse_json_or_raise(resp, "getWebKey")
            if data.get("code") == 0 and data.get("data"):
                return data["data"]
        fallback = app_sign({"disable_rcmd": "0", "local_id": self.buvid})
        data2 = parse_json_or_raise(
            self.session.get(GET_WEB_KEY, params=fallback, timeout=20),
            "getWebKey(fallback)",
        )
        if data2.get("code") != 0:
            raise ApiError(f"getWebKey 失败: {data2}")
        return data2["data"]

    def send_sms_code(self, tel: str, cid: int, captcha: CaptchaInfo) -> Dict[str, Any]:
        ts_ms = int(time.time() * 1000)
        payload = {
            "build": "2001100",
            "buvid": self.buvid,
            "c_locale": "zh_CN",
            "channel": "master",
            "cid": cid,
            "disable_rcmd": "0",
            "gee_challenge": captcha.gee_challenge,
            "gee_seccode": captcha.gee_seccode,
            "gee_validate": captcha.gee_validate,
            "local_id": self.buvid,
            "login_session_id": hashlib.md5(f"{self.buvid}{ts_ms}".encode()).hexdigest(),
            "mobi_app": "android_hd",
            "platform": "android",
            "recaptcha_token": captcha.recaptcha_token,
            "s_locale": "zh_CN",
            "statistics": STATISTICS,
            "tel": tel,
            "ts": str(ts_ms // 1000),
        }
        resp = self.session.post(APP_SMS_SEND, data=app_sign(payload), timeout=20)
        return parse_json_or_raise(resp, "sendSmsCode")

    def login_by_sms(
        self,
        tel: str,
        cid: int,
        sms_code: str,
        captcha_key: str,
        public_key_pem: str,
    ) -> Dict[str, Any]:
        pub = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        dt_enc = pub.encrypt(random_str(16).encode("utf-8"), padding.PKCS1v15())
        payload = {
            "bili_local_id": self.device_id,
            "build": "2001100",
            "buvid": self.buvid,
            "c_locale": "zh_CN",
            "captcha_key": captcha_key,
            "channel": "master",
            "cid": cid,
            "code": sms_code,
            "device": "phone",
            "device_id": self.device_id,
            "device_name": "vivo",
            "device_platform": "Android14vivo",
            "disable_rcmd": "0",
            "dt": quote(base64.b64encode(dt_enc).decode("utf-8"), safe=""),
            "from_pv": "main.my-information.my-login.0.click",
            "from_url": quote("bilibili://user_center/mine", safe=""),
            "local_id": self.buvid,
            "mobi_app": "android_hd",
            "platform": "android",
            "s_locale": "zh_CN",
            "statistics": STATISTICS,
            "tel": tel,
        }
        resp = self.session.post(APP_SMS_LOGIN, data=app_sign(payload), timeout=20)
        return parse_json_or_raise(resp, "loginBySms")

    def qr_confirm_with_credentials(self, qr_url_or_code: str, cred_path: Path) -> Dict[str, Any]:
        cred = load_saved_credentials(cred_path)
        cookies = cred.get("cookies") or {}
        if not cookies:
            raise SystemExit(f"凭证文件缺少 cookies: {cred_path}")

        csrf = cookies.get("bili_jct")
        if not csrf:
            raise SystemExit("凭证 cookies 缺少 bili_jct，无法完成 qrcode confirm。")

        auth_code = parse_auth_code(qr_url_or_code)

        # 注入登录 cookie
        for name, value in cookies.items():
            if value is None:
                continue
            self.session.cookies.set(name, str(value), domain=".bilibili.com", path="/")

        headers = {
            "referer": "https://passport.bilibili.com/",
            "origin": "https://passport.bilibili.com",
        }
        payload = {
            "auth_code": auth_code,
            "csrf": csrf,
            "scanning_type": "1",
        }
        resp = self.session.post(QRCODE_CONFIRM, data=payload, headers=headers, timeout=20)
        return parse_json_or_raise(resp, "qrcodeConfirm")


def save_credentials(login_data: Dict[str, Any], output: Path) -> None:
    token = login_data.get("token_info") or {}
    cookie_list = (login_data.get("cookie_info") or {}).get("cookies") or []
    cookies = {c.get("name"): c.get("value") for c in cookie_list if c.get("name")}
    output.write_text(
        json.dumps(
            {
                "saved_at": int(time.time()),
                "access_token": token.get("access_token"),
                "refresh_token": token.get("refresh_token"),
                "expires_in": token.get("expires_in"),
                "mid": token.get("mid"),
                "cookies": cookies,
                "raw_token_info": token,
                "raw_cookie_info": cookie_list,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )


def run_sms_login(args: argparse.Namespace) -> None:
    print("=== B 站 App 短信登录脚本 ===")
    print(f"当前签名 APP_KEY: {APP_KEY}")
    print("提示：同一批 token + sign 接口必须使用同一组 APP_KEY/APP_SEC。")

    tel = args.tel or input("手机号(不含+): ").strip()
    cid = args.cid if args.cid is not None else int((input("国家码(中国大陆填86，默认86): ").strip() or "86"))

    client = BiliClient()
    try:
        key_data = client.get_web_key()
    except Exception as e:
        raise SystemExit(
            "获取 web key 失败。\n"
            f"错误: {e}\n"
            "提示: 如果返回的是 HTML，通常是网络代理/风控页导致；可尝试更换网络、关闭抓包代理、或直连后重试。"
        )

    sms_resp = client.send_sms_code(tel, cid, CaptchaInfo())
    print("[sendSmsCode]", sms_resp)

    if sms_resp.get("code") != 0:
        recaptcha_url = (sms_resp.get("data") or {}).get("recaptcha_url")
        if recaptcha_url:
            c = parse_recaptcha_url(recaptcha_url)
            print("\n触发人机验证，请在外部完成 Geetest 后填写以下参数：")
            print("recaptcha_token:", c.recaptcha_token)
            print("gee_gt:", c.gee_gt)
            print("gee_challenge:", c.gee_challenge)
            c.gee_validate = input("gee_validate: ").strip()
            c.gee_seccode = input("gee_seccode: ").strip()
            sms_resp = client.send_sms_code(tel, cid, c)
            print("[sendSmsCode retry]", sms_resp)

    if sms_resp.get("code") != 0:
        raise SystemExit(f"发送短信失败: {sms_resp}")

    captcha_key = (sms_resp.get("data") or {}).get("captcha_key")
    if not captcha_key:
        raise SystemExit(f"未拿到 captcha_key: {sms_resp}")

    sms_code = args.sms_code or input("请输入短信验证码: ").strip()
    login_resp = client.login_by_sms(tel, cid, sms_code, captcha_key, key_data["key"])
    print("[loginBySms]", login_resp)
    if login_resp.get("code") != 0:
        raise SystemExit(f"登录失败: {login_resp}")

    data = login_resp.get("data") or {}
    if not data.get("token_info") or not data.get("cookie_info"):
        raise SystemExit(f"登录返回缺少 token_info/cookie_info: {login_resp}")

    out_file = Path(args.output)
    save_credentials(data, out_file)
    print(f"登录成功，凭证已保存到: {out_file.resolve()}")


def run_qr_confirm(args: argparse.Namespace) -> None:
    client = BiliClient()
    result = client.qr_confirm_with_credentials(args.qr, Path(args.cred))
    print("[qrcodeConfirm]", result)
    if result.get("code") != 0:
        raise SystemExit(f"扫码确认失败: {result}")
    print("扫码确认成功。")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="B 站 App 短信登录 & 凭证扫码确认")
    sub = parser.add_subparsers(dest="cmd", required=False)

    p_sms = sub.add_parser("sms-login", help="短信登录并保存凭证")
    p_sms.add_argument("--tel", help="手机号（不含+）")
    p_sms.add_argument("--cid", type=int, help="国家码，默认 86")
    p_sms.add_argument("--sms-code", help="短信验证码（不传则交互输入）")
    p_sms.add_argument("--output", default="bili_credentials.json", help="凭证输出文件")

    p_qr = sub.add_parser("qr-confirm", help="用保存的凭证确认二维码登录")
    p_qr.add_argument("--qr", required=True, help="二维码解码出来的完整链接（或 auth_code）")
    p_qr.add_argument("--cred", default="bili_credentials.json", help="凭证文件路径")

    return parser


def main() -> None:
    ensure_key_pair_valid()
    parser = build_parser()
    args = parser.parse_args()

    # 兼容旧版本：不带子命令时默认跑短信登录
    if args.cmd in (None, "sms-login"):
        run_sms_login(args)
    elif args.cmd == "qr-confirm":
        run_qr_confirm(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
