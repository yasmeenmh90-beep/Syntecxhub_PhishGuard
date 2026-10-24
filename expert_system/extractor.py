"""Turn a raw email or text message into facts for the rule engine.

This is the "perception" layer: it reads the message the way a careful human
would and records each warning sign as a fact with a certainty and the exact
text that triggered it (so the UI can highlight it). The rule engine then does
all of the reasoning.

Everything runs offline with the standard library. No link is ever opened.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from email import message_from_string
from email.utils import parseaddr
from html import unescape
from html.parser import HTMLParser
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

# Organisations whose names scammers borrow, with the domains they really use.
# The fictional ones (Northwind Bank, ParcelPost, StreamFlix, CloudVault) are
# used by the bundled sample messages.
BRANDS: Dict[str, Tuple[str, ...]] = {
    "paypal": ("paypal.com",),
    "apple": ("apple.com", "icloud.com"),
    "microsoft": ("microsoft.com", "outlook.com", "live.com", "office.com"),
    "amazon": ("amazon.com", "amazon.co.uk", "amazon.ae", "amazon.fr"),
    "netflix": ("netflix.com",),
    "google": ("google.com", "gmail.com"),
    "dhl": ("dhl.com",),
    "fedex": ("fedex.com",),
    "ups": ("ups.com",),
    "linkedin": ("linkedin.com",),
    "instagram": ("instagram.com",),
    "facebook": ("facebook.com", "facebookmail.com"),
    "whatsapp": ("whatsapp.com",),
    "northwind bank": ("northwindbank.com",),
    "parcelpost": ("parcelpost.com",),
    "streamflix": ("streamflix.com",),
    "cloudvault": ("cloudvault.com",),
}
DISPLAY = {"paypal": "PayPal", "parcelpost": "ParcelPost", "streamflix": "StreamFlix", "cloudvault": "CloudVault",
           "dhl": "DHL", "ups": "UPS", "fedex": "FedEx", "linkedin": "LinkedIn", "whatsapp": "WhatsApp"}


def nice(brand: str) -> str:
    """Display name for a brand key."""
    return DISPLAY.get(brand, brand.title() if brand.islower() else brand)


FREE_MAIL = ("gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "proton.me",
             "protonmail.com", "icloud.com", "mail.com", "gmx.com", "yandex.com")
SHORTENERS = ("bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
              "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "tiny.cc")
RISKY_TLDS = ("xyz", "top", "click", "zip", "mov", "icu", "buzz", "monster", "rest", "cam", "cfd", "sbs",
              "quest", "gq", "tk", "ml", "cf", "ga", "support", "live")
RISKY_EXT = ("zip", "rar", "7z", "exe", "scr", "js", "vbs", "html", "htm", "iso", "img", "lnk", "docm",
             "xlsm", "bat", "cmd", "msi", "jar")

PHRASES: Dict[str, Tuple[str, ...]] = {
    "urgent_tone": (r"\burgent(?:ly)?\b", r"\bimmediately\b", r"\bact now\b", r"\bright away\b", r"\bASAP\b",
                    r"\bwithin \d+ ?(?:hours?|hrs?|minutes?|mins?|days?)\b", r"\btoday only\b", r"\bfinal (?:notice|warning|reminder)\b",
                    r"\blast chance\b", r"\bexpires? (?:today|soon|in)\b", r"\bbefore it'?s too late\b", r"\bas soon as possible\b"),
    "threat_language": (r"\bsuspend(?:ed|ion)?\b", r"\blocked\b", r"\bdeactivat\w*", r"\bterminat\w*", r"\bclosed? permanently\b",
                        r"\blegal action\b", r"\bunauthori[sz]ed (?:access|activity|login|transaction)", r"\bunusual (?:activity|sign-?in)",
                        r"\bpenalt(?:y|ies)\b", r"\bfine[sd]?\b(?! print)", r"\barrest\b", r"\bpermanently (?:deleted|lost)\b", r"\bcompromised\b"),
    "prize_bait": (r"\byou(?:'ve| have)? won\b", r"\bwinner\b", r"\bcongratulations\b", r"\bclaim your\b", r"\bprize\b",
                   r"\blottery\b", r"\bfree (?:gift|iphone|reward)\b", r"\brefund (?:of|is available|pending)\b", r"\breward\b", r"\bcash ?back\b"),
    "secrecy_request": (r"\bkeep (?:this|it) (?:confidential|between us|quiet|private)\b", r"\bdon'?t (?:tell|mention|discuss)\b",
                        r"\bconfidential\b", r"\bdiscreet(?:ly)?\b", r"\bdo not share this\b"),
    "asks_credentials": (r"\bverify your (?:account|identity|details|information)\b", r"\bconfirm your (?:account|identity|password|login|details)\b",
                         r"\blog ?in\b", r"\bsign ?in\b", r"\bpassword\b", r"\b(?:one[- ]time|verification|security) code\b", r"\bOTP\b",
                         r"\bPIN\b", r"\breset your password\b", r"\bupdate your (?:account|login|credentials)\b", r"\bre-?activate\b"),
    "asks_payment": (r"\bgift ?cards?\b", r"\bwire transfer\b", r"\bbank transfer\b", r"\bbitcoin\b", r"\bcrypto(?:currency)?\b",
                     r"\b(?:customs|delivery|shipping|processing|release|admin(?:istration)?) fee\b", r"\bpay(?:ment)? (?:of|now|the)\b",
                     r"\b(?:USD|EUR|AED|GBP|\$|€|£)\s?\d", r"\b\d+(?:[.,]\d+)?\s?(?:USD|EUR|AED|GBP|dollars|euros)\b", r"\boutstanding (?:balance|amount|invoice)\b"),
    "asks_code": (r"\b(?:send|forward|share|tell|give) (?:it |me |us )?(?:back )?(?:the |that |your )?(?:\d-digit )?(?:verification |security |one[- ]time |login |OTP )?code\b",
                  r"\b(?:\d|six)-digit (?:verification |security )?code\b", r"\bcode (?:you|that you) (?:just )?received\b",
                  r"\bsent you a (?:\d-digit |verification |security )?code\b"),
    "asks_personal_data": (r"\bcard (?:number|details)\b", r"\bCVV\b", r"\bexpiry date\b", r"\bdate of birth\b", r"\bpassport\b",
                           r"\b(?:social security|national id|emirates id|ID) (?:number|card|copy)\b", r"\bbank (?:account number|details)\b",
                           r"\bbilling (?:information|details|address)\b"),
    "generic_greeting": (r"\bdear (?:customer|user|client|member|account holder|valued \w+|sir|madam|sir/madam)\b", r"^\s*hello,?\s*$",
                         r"\bdear (?:beneficiary|winner)\b"),
}

URL_RE = re.compile(r"""(?i)\b((?:https?://|www\.)[^\s<>"')\]]+|(?:[a-z0-9-]+\.)+(?:com|net|org|info|biz|io|co|ly|xyz|top|click|zip|icu|live|support|me|uk|ae|fr|de)(?:/[^\s<>"')\]]*)?)""")
ATTACH_RE = re.compile(r"(?i)\b[\w\-. ]{1,60}\.(" + "|".join(RISKY_EXT) + r")\b")


@dataclass
class Signal:
    fact: str
    cf: float
    reason: str
    spans: List[Tuple[int, int]] = field(default_factory=list)   # offsets in Extraction.text

    def to_dict(self) -> dict:
        d = asdict(self)
        d["spans"] = [list(s) for s in self.spans]
        return d


@dataclass
class Extraction:
    text: str                       # the message as displayed (headers + body)
    kind: str                       # "email" or "text message"
    sender: Optional[str]
    links: List[dict]
    signals: Dict[str, Signal]

    @property
    def facts(self) -> Dict[str, float]:
        return {k: s.cf for k, s in self.signals.items()}

    def to_dict(self) -> dict:
        return {"text": self.text, "kind": self.kind, "sender": self.sender, "links": self.links,
                "signals": {k: s.to_dict() for k, s in self.signals.items()}}


class _Anchors(HTMLParser):
    """Collect (visible text, href) pairs and plain text from an HTML body."""

    def __init__(self) -> None:
        super().__init__()
        self.anchors: List[Tuple[str, str]] = []
        self.text: List[str] = []
        self._href: Optional[str] = None
        self._buf: List[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._buf = []
        elif tag in ("br", "p", "div", "tr"):
            self.text.append("\n")

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            label = "".join(self._buf).strip()
            self.anchors.append((label, self._href))
            self.text.append(f"{label} [{self._href}]")
            self._href = None

    def handle_data(self, data):
        if self._href is not None:
            self._buf.append(data)
        else:
            self.text.append(data)


# ----------------------------------------------------------------- helpers
def host_of(url: str) -> str:
    if not re.match(r"(?i)^[a-z]+://", url):
        url = "http://" + url
    host = (urlparse(url).hostname or "").lower().rstrip(".")
    return host[4:] if host.startswith("www.") else host


def registered_domain(host: str) -> str:
    """Rough registrable domain: last two labels (three for co.uk-style)."""
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "ac", "gov") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _normalise_lookalike(s: str) -> str:
    table = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
    return s.translate(table).replace("rn", "m").replace("vv", "w")


def brand_for_domain(host: str) -> Optional[str]:
    """Return the brand a domain imitates, or None if it is official or unrelated."""
    reg = registered_domain(host)
    for brand, domains in BRANDS.items():
        if reg in domains or any(host == d or host.endswith("." + d) for d in domains):
            return None  # genuinely theirs
    squashed = _normalise_lookalike(host.replace("-", "").replace(".", ""))
    if host.startswith("xn--") or ".xn--" in host:
        return "an internationalised (punycode) domain"
    for brand, domains in BRANDS.items():
        keys = {brand.replace(" ", "")} | {_normalise_lookalike(d.split(".")[0]) for d in domains}
        for key in keys:
            if len(key) < 4:
                continue
            if key in squashed or (len(key) >= 6 and _near(key, squashed)):
                return brand
    return None


def _near(key: str, text: str) -> bool:
    """True if ``text`` contains ``key`` with exactly one wrong letter (e.g. streamfiix)."""
    n = len(key)
    for i in range(len(text) - n + 1):
        if sum(a != b for a, b in zip(text[i:i + n], key)) == 1:
            return True
    return False


def is_official(host: str) -> bool:
    reg = registered_domain(host)
    return any(reg in ds for ds in BRANDS.values())


# ----------------------------------------------------------------- parsing
def _split_email(raw: str) -> Tuple[Optional[dict], str, List[Tuple[str, str]], List[str]]:
    """If ``raw`` looks like an email with headers, return (headers, body, anchors, attachments)."""
    head = raw.lstrip()[:600]
    if not re.search(r"(?im)^(from|subject|to|reply-to|date):", head):
        return None, raw, [], []
    msg = message_from_string(raw.lstrip())
    headers = {k.lower(): str(v) for k, v in msg.items()}
    anchors: List[Tuple[str, str]] = []
    attachments: List[str] = []
    bodies: List[str] = []
    parts = msg.walk() if msg.is_multipart() else [msg]
    for part in parts:
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if filename:
            attachments.append(filename)
            continue
        payload = part.get_payload(decode=True)
        text = payload.decode(part.get_content_charset() or "utf-8", "replace") if isinstance(payload, bytes) else str(part.get_payload())
        if part.get_content_type() == "text/html" or re.search(r"(?i)<(html|a\s|p>|div|br)", text):
            parser = _Anchors()
            parser.feed(text)
            anchors.extend(parser.anchors)
            text = unescape("".join(parser.text))
        bodies.append(text.strip())
    return headers, "\n\n".join(b for b in bodies if b), anchors, attachments


def extract(raw: str) -> Extraction:
    """Read a message and return the warning signs it contains."""
    raw = (raw or "").replace("\r\n", "\n").strip()
    headers, body, anchors, attachments = _split_email(raw)

    # The displayed text: key headers first (so sender issues can be highlighted), then the body.
    if headers is not None:
        shown = [f"{name.title()}: {headers[name]}" for name in ("from", "reply-to", "subject") if name in headers]
        text = "\n".join(shown) + "\n\n" + body
        kind = "email"
    else:
        text, kind = raw, "text message"
    signals: Dict[str, Signal] = {}

    def add(fact: str, cf: float, reason: str, spans=()) -> None:
        sig = signals.get(fact)
        if sig is None:
            signals[fact] = Signal(fact, cf, reason, list(spans))
        else:
            if abs(cf) > abs(sig.cf):
                sig.cf, sig.reason = cf, reason
            sig.spans.extend(s for s in spans if s not in sig.spans)

    def find(needle: str) -> List[Tuple[int, int]]:
        return [(m.start(), m.end()) for m in re.finditer(re.escape(needle), text, re.I)] if needle else []

    # --- language patterns -------------------------------------------------
    for fact, patterns in PHRASES.items():
        hits: List[Tuple[int, int]] = []
        words: List[str] = []
        for pat in patterns:
            for m in re.finditer(pat, text, re.I | re.M):
                hits.append((m.start(), m.end()))
                words.append(m.group(0).strip())
        if hits:
            unique = list(dict.fromkeys(w.lower() for w in words))
            cf = 1.0 if len(unique) >= 2 or fact in ("generic_greeting", "secrecy_request") else 0.8
            if fact == "asks_credentials" and unique and set(unique) <= {"log in", "login", "sign in", "signin"}:
                cf = 0.6   # "sign in" alone is weaker than "verify your password"
            add(fact, cf, "Found: " + ", ".join(f"“{w}”" for w in unique[:4]), hits)

    # --- brand claims ------------------------------------------------------
    # An email "claims" a brand when it appears in the sender name, the subject,
    # or more than once in the body; a text message is short, so any mention counts.
    from_name = parseaddr(headers.get("from", ""))[0] if headers else ""
    subject = headers.get("subject", "") if headers else ""
    brand_hits = []
    for brand in BRANDS:
        hits = [(m.start(), m.end()) for m in re.finditer(r"\b" + re.escape(brand) + r"\b", text, re.I)]
        in_header = re.search(r"\b" + re.escape(brand) + r"\b", from_name + " " + subject, re.I)
        if hits and (headers is None or in_header or len(hits) >= 2):
            brand_hits.extend((brand, h) for h in hits)
    for m in re.finditer(r"\b(?:your|the) bank\b", text, re.I):
        brand_hits.append(("a bank", (m.start(), m.end())))
    claimed = list(dict.fromkeys(b for b, _ in brand_hits))
    if claimed:
        add("claims_brand", 1.0, "Presents itself as " + ", ".join(nice(b) for b in claimed[:3]), [s for _, s in brand_hits])
    role = re.search(r"\b(CEO|CFO|COO|director|manager|HR|IT support|helpdesk|administrator|admin)\b", from_name, re.I)

    # --- sender -------------------------------------------------------------
    sender = None
    if headers is not None and "from" in headers:
        name, addr = parseaddr(headers["from"])
        sender = addr or headers["from"]
        sender_domain = addr.split("@")[-1].lower() if "@" in addr else ""
        from_spans = find(addr) or find(headers["from"])
        if sender_domain:
            looks_like = brand_for_domain(sender_domain)
            if looks_like:
                add("lookalike_domain", 1.0, f"Sender domain {sender_domain} imitates {nice(looks_like)}", from_spans)
            if sender_domain in FREE_MAIL and claimed:
                add("free_mail_brand", 1.0, f"Claims to be {nice(claimed[0])} but writes from {sender_domain}", from_spans)
            if sender_domain in FREE_MAIL and role:
                add("claims_brand", 0.8, f"Writes as an official role ({role.group(0)})", find(from_name))
                add("free_mail_brand", 1.0, f"Writes as {from_name} from a free {sender_domain} account", from_spans)
            name_brands = [b for b in BRANDS if re.search(r"\b" + re.escape(b) + r"\b", name or "", re.I)]
            claimed_official = [b for b in claimed if b in BRANDS]
            if claimed_official and not any(registered_domain(sender_domain) in BRANDS[b] for b in claimed_official):
                strength = 1.0 if name_brands else 0.7
                add("sender_mismatch", strength,
                    f"Says it is {nice(claimed_official[0])} but the address is @{sender_domain}", from_spans)
            elif claimed_official:
                add("sender_mismatch", -0.8, f"Sender domain {sender_domain} belongs to {nice(claimed_official[0])}", from_spans)
        if "reply-to" in headers:
            _, reply = parseaddr(headers["reply-to"])
            if "@" in reply and "@" in (addr or "") and registered_domain(reply.split("@")[-1].lower()) != registered_domain(sender_domain):
                add("reply_to_mismatch", 1.0, f"Replies go to {reply}, not {sender_domain}", find(reply))

    # --- links ---------------------------------------------------------------
    links: List[dict] = []
    seen = set()
    for label, href in anchors:
        h = host_of(href)
        label_host = host_of(label) if URL_RE.fullmatch(label.strip() or "-") else ""
        links.append({"url": href, "host": h, "label": label})
        seen.add(href)
        if label_host and registered_domain(label_host) != registered_domain(h):
            add("link_text_mismatch", 1.0, f"Text shows {label_host} but the link goes to {h}", find(label) + find(href))
    for m in URL_RE.finditer(text):
        url = m.group(0).rstrip(".,;:!?")
        bare = not re.match(r"(?i)https?://|www\.", url)
        before = text[m.start() - 1] if m.start() > 0 else " "
        after = text[m.start() + len(url)] if m.start() + len(url) < len(text) else " "
        if before == "@" or (bare and (before.isalnum() or before in "._-" or after.isalnum() or after in "@_-")):
            continue                                   # part of an email address or a longer word
        if bare and url.rsplit(".", 1)[-1].split("/")[0].lower() in RISKY_EXT:
            continue                                   # a file name such as invoice.zip
        if bare and ATTACH_RE.fullmatch(url):
            continue
        if url in seen or any(url in l["url"] for l in links):
            continue
        seen.add(url)
        links.append({"url": url, "host": host_of(url), "label": ""})
    if links:
        add("has_links", 1.0, f"{len(links)} link(s) found", [])
    for link in links:
        url, h = link["url"], link["host"]
        spans = find(url)
        if not h:
            continue
        if h in SHORTENERS or registered_domain(h) in SHORTENERS:
            add("url_shortener", 1.0, f"{h} is a link shortener", spans)
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", h):
            add("ip_address_link", 1.0, f"Link goes to the raw IP address {h}", spans)
        imitates = brand_for_domain(h)
        if imitates:
            add("lookalike_domain", 1.0, f"{h} imitates {nice(imitates)}", spans)
        tld = h.rsplit(".", 1)[-1]
        if tld in RISKY_TLDS and not is_official(h):
            add("suspicious_tld", 0.8, f".{tld} domains are often used for throwaway scam sites", spans)
        if url.lower().startswith("http://"):
            add("insecure_link", 1.0, f"{h} uses unencrypted http://", spans)
    hosts = [l["host"] for l in links if l["host"]]
    if hosts and all(is_official(h) for h in hosts):
        add("lookalike_domain", -0.6, "All links point to official domains", [])
    claimed_real = [b for b in claimed if b in BRANDS]
    if claimed_real and hosts:
        official = {d for b in claimed_real for d in BRANDS[b]}
        off_brand = [h for h in hosts if registered_domain(h) not in official]
        if off_brand:
            add("brand_link_mismatch", 1.0, f"Names {nice(claimed_real[0])} but links to {off_brand[0]}",
                [sp for l in links if l["host"] in off_brand for sp in find(l["url"])])
        else:
            add("brand_link_mismatch", -1.0, f"Every link goes to {nice(claimed_real[0])}'s own domain", [])

    # --- attachments ----------------------------------------------------------
    risky = [a for a in attachments if a.rsplit(".", 1)[-1].lower() in RISKY_EXT]
    risky_spans: List[Tuple[int, int]] = []
    for m in ATTACH_RE.finditer(text):
        risky.append(m.group(0).strip())
        risky_spans.append((m.start(), m.end()))
    risky = [r for r in dict.fromkeys(risky) if not URL_RE.fullmatch(r)]
    if risky:
        add("risky_attachment", 1.0, "Risky file: " + ", ".join(risky[:3]), risky_spans)

    for sig in signals.values():
        sig.spans = sorted(set(sig.spans))
    return Extraction(text=text, kind=kind, sender=sender, links=links, signals=signals)
