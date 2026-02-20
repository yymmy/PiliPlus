#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""B 站 App 短信登录脚本（基于 PiliPlus 登录实现）

流程：
1) 获取 web key
2) 发送短信验证码（必要时补充 geetest 参数重试）
3) 提交短信验证码登录
4) 保存 access_token / refresh_token / cookies 到本地 JSON
"""

from __future__ import annotations

import base64
import hashlib
import json
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

APP_KEY = "dfca71928277209b"
APP_SEC = "b5475a8825547a4fc26c7d518eaaa02e"

PASSPORT_BASE = "https://passport.bilibili.com"
GET_WEB_KEY = f"{PASSPORT_BASE}/x/passport-login/web/key"
APP_SMS_SEND = f"{PASSPORT_BASE}/x/passport-login/sms/send"
APP_SMS_LOGIN = f"{PASSPORT_BASE}/x/passport-login/login/sms"

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
    query = urlencode(items)
    data["sign"] = hashlib.md5((query + APP_SEC).encode("utf-8")).hexdigest()
    return data


def random_str(n: int = 16) -> str:
    s = string.ascii_letters + string.digits
    return "".join(random.choice(s) for _ in range(n))


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


class BiliSmsClient:
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
        resp2 = self.session.get(GET_WEB_KEY, params=fallback, timeout=20)
        data2 = parse_json_or_raise(resp2, "getWebKey(fallback)")
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
        signed = app_sign(payload)
        resp = self.session.post(APP_SMS_SEND, data=signed, timeout=20)
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
        dt = quote(base64.b64encode(dt_enc).decode("utf-8"), safe="")

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
            "dt": dt,
            "from_pv": "main.my-information.my-login.0.click",
            "from_url": quote("bilibili://user_center/mine", safe=""),
            "local_id": self.buvid,
            "mobi_app": "android_hd",
            "platform": "android",
            "s_locale": "zh_CN",
            "statistics": STATISTICS,
            "tel": tel,
        }
        signed = app_sign(payload)
        resp = self.session.post(APP_SMS_LOGIN, data=signed, timeout=20)
        return parse_json_or_raise(resp, "loginBySms")


def save_credentials(login_data: Dict[str, Any], output: Path) -> None:
    token = login_data.get("token_info") or {}
    cookie_list = (login_data.get("cookie_info") or {}).get("cookies") or []
    cookies = {c.get("name"): c.get("value") for c in cookie_list if c.get("name")}

    out = {
        "saved_at": int(time.time()),
        "access_token": token.get("access_token"),
        "refresh_token": token.get("refresh_token"),
        "expires_in": token.get("expires_in"),
        "mid": token.get("mid"),
        "cookies": cookies,
        "raw_token_info": token,
        "raw_cookie_info": cookie_list,
    }
    output.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")


def main() -> None:
    print("=== B 站 App 短信登录脚本 ===")
    tel = input("手机号(不含+): ").strip()
    cid_txt = input("国家码(中国大陆填86，默认86): ").strip()
    cid = int(cid_txt) if cid_txt else 86

    client = BiliSmsClient()

    try:
        key_data = client.get_web_key()
    except Exception as e:
        raise SystemExit(
            "获取 web key 失败。\n"
            f"错误: {e}\n"
            "提示: 如果返回的是 HTML，通常是网络代理/风控页导致；可尝试更换网络、关闭抓包代理、或直连后重试。"
        )

    pub_key = key_data["key"]
    captcha = CaptchaInfo()

    sms_resp = client.send_sms_code(tel, cid, captcha)
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

    sms_code = input("请输入短信验证码: ").strip()
    login_resp = client.login_by_sms(tel, cid, sms_code, captcha_key, pub_key)
    print("[loginBySms]", login_resp)

    if login_resp.get("code") != 0:
        raise SystemExit(f"登录失败: {login_resp}")

    data = login_resp.get("data") or {}
    if not data.get("token_info") or not data.get("cookie_info"):
        raise SystemExit(f"登录返回缺少 token_info/cookie_info: {login_resp}")

    out_file = Path("bili_credentials.json")
    save_credentials(data, out_file)
    print(f"登录成功，凭证已保存到: {out_file.resolve()}")


if __name__ == "__main__":
    main()
