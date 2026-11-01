"""English and Turkish strings. The Ghost session has no settings of its own,
so the language follows the system's (LANG), English otherwise."""
from __future__ import annotations

import os

STRINGS: dict[str, dict[str, str]] = {
    "en": {
        "tip_minimize": "Minimize",
        "tip_close": "Close",
        "eyebrow": "GHOST SESSION",
        "title": "Nothing in this session is kept.",
        "sub": "You are using a separate account that lives in memory. Your own files "
               "are not here, and everything you do goes through Tor.",
        "tor_wait": "Connecting to Tor…",
        "tor_wait_d": "Nothing can reach the internet until Tor is connected — not even "
                      "by accident.",
        "tor_ok": "Everything goes through Tor",
        "tor_ok_d": "Websites see a Tor address ({ip}), not yours.",
        "tor_slow": "Tor is not connected yet",
        "tor_slow_d": "The network may be blocking Tor. Until it connects, nothing goes "
                      "out at all. Bridges can be added in /etc/maze-ghost/torrc.d/.",
        "mem": "It lives in memory",
        "mem_d": "Logging out erases this session: files, history, saved Wi-Fi passwords, "
                 "everything.",
        "swap": "Swap on disk: {dev}",
        "swap_d": "If memory runs short, parts of this session can be written there "
                  "and outlive it. Close what you do not need.",
        "keep": "To keep a file, put it in a capsule",
        "keep_d": "Encrypted Maze Capsules are the one thing a Ghost session keeps. "
                  "Everything else is gone at logout.",
        "btn_capsule": "Open Maze Capsule",
        "btn_ok": "I understand",
    },
    "tr": {
        "tip_minimize": "Küçült",
        "tip_close": "Kapat",
        "eyebrow": "GHOST OTURUMU",
        "title": "Bu oturumda hiçbir şey saklanmaz.",
        "sub": "Bellekte yaşayan ayrı bir hesap kullanıyorsunuz. Kendi dosyalarınız "
               "burada değil ve yaptığınız her şey Tor üzerinden gider.",
        "tor_wait": "Tor'a bağlanılıyor…",
        "tor_wait_d": "Tor bağlanana kadar hiçbir şey internete çıkamaz — kazara bile.",
        "tor_ok": "Her şey Tor üzerinden gidiyor",
        "tor_ok_d": "Siteler sizin adresinizi değil, bir Tor adresi ({ip}) görüyor.",
        "tor_slow": "Tor henüz bağlanmadı",
        "tor_slow_d": "Ağ Tor'u engelliyor olabilir. Bağlanana kadar dışarı hiçbir şey "
                      "çıkmaz. Köprüler /etc/maze-ghost/torrc.d/ içine eklenebilir.",
        "mem": "Bellekte yaşıyor",
        "mem_d": "Çıkış yapınca bu oturum silinir: dosyalar, geçmiş, kaydedilen Wi-Fi "
                 "şifreleri, her şey.",
        "swap": "Diskte swap var: {dev}",
        "swap_d": "Bellek yetmezse bu oturumun parçaları oraya yazılabilir ve oturumdan "
                  "sonra kalabilir. Gerekmeyenleri kapatın.",
        "keep": "Bir dosyayı saklamak için onu bir kapsüle koyun",
        "keep_d": "Şifreli Maze Capsule'lar, Ghost oturumunun sakladığı tek şeydir. "
                  "Geri kalan her şey çıkışta gider.",
        "btn_capsule": "Maze Capsule'ı aç",
        "btn_ok": "Anladım",
    },
}

_lang = "tr" if (os.environ.get("LANG") or "").startswith("tr") else "en"


def set_language(lang: str) -> None:
    global _lang
    _lang = lang if lang in STRINGS else "en"


def t(key: str, /, **kw) -> str:
    text = STRINGS.get(_lang, {}).get(key) or STRINGS["en"].get(key) or key
    return text.format(**kw) if kw else text
