"""App Store screenshots for Verrou: one message per screen, the app's real UI
in a phone frame, rendered by headless Brave or Chrome (BROWSER overrides the
path) in <out-dir>/6.3in (1206x2622, the "iPhone with Dynamic Island, medium
display" slot App Store Connect asks for) and <out-dir>/6.9in (1320x2868).
Both have the same aspect ratio: the 6.3" set is the 6.9" one resampled.

  SIM_DEVICE_TYPE=com.apple.CoreSimulator.SimDeviceType.iPhone-17-Pro-Max \
    APPEARANCES=light OUT=target/store-en scripts/ios-showcase.sh
  python3 -I scripts/app-store-screenshots.py target/store-en/clair target/store-en/final en

(SHOWCASE_LANG=fr-FR and `fr` for the French listing.) <raw-dir> holds the
simulator captures named as in SLIDES; the texts follow docs/app-store.
"""
import base64, html, os, subprocess, sys, tempfile
from pathlib import Path

W, H = 1320, 2868
# App Store Connect sizes (portrait) rendered from the W x H page.
SIZES = {"6.9in": (1320, 2868), "6.3in": (1206, 2622)}
BRAVE = os.environ.get("BROWSER", "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser")

# (raw capture, background, {lang: (kicker, headline with *highlight*, footer)})
SLIDES = [
    ("03-vault", ("#3F48D8", "#6B4FE0"), {
        "en": ("For your Vaultwarden", "Your passwords.\n*Your server.*", "Open source · Bitwarden encryption"),
        "fr": ("Pour votre Vaultwarden", "Vos mots de passe.\n*Votre serveur.*", "Open source · chiffrement Bitwarden"),
    }),
    ("02-locked", ("#14161F", "#2A2F45"), {
        "en": ("Face ID", "Unlocked\nin a *glance*", "Your master password never leaves the device"),
        "fr": ("Face ID", "Déverrouillé\nd'un *regard*", "Le mot de passe principal reste sur l'iPhone"),
    }),
    ("07-search", ("#0E8F7E", "#1BB39A"), {
        "en": ("Instant search", "Find anything\nas you *type*", "Thousands of items, typos forgiven"),
        "fr": ("Recherche instantanée", "Tout retrouver\nen *tapant*", "Des milliers d'éléments, fautes comprises"),
    }),
    ("08-item", ("#525CF2", "#7C83F7"), {
        "en": ("Two-factor codes built in", "Passwords and\ncodes, *together*", "One-time codes and passkeys in one place"),
        "fr": ("Double authentification intégrée", "Mots de passe\net codes *réunis*", "Codes à usage unique et passkeys au même endroit"),
    }),
    ("11-generator", ("#E8613C", "#F28A4B"), {
        "en": ("Generator", "Strong passwords\nin *one tap*", "Random or memorable passphrases"),
        "fr": ("Générateur", "Des mots de passe\nsolides en *un geste*", "Aléatoires ou phrases faciles à retenir"),
    }),
    ("13-audit", ("#B42357", "#D9456F"), {
        "en": ("Security audit", "Fix weak and\n*reused* passwords", "Breach checks without sending your passwords"),
        "fr": ("Audit de sécurité", "Corrigez les mots\nde passe *faibles*", "Fuites vérifiées sans envoyer vos mots de passe"),
    }),
    ("04-list", ("#2B3A55", "#41557A"), {
        "en": ("Everything in one vault", "Logins, cards,\n*notes* and more", "Works with the Bitwarden apps you already use"),
        "fr": ("Tout dans un seul coffre", "Identifiants,\ncartes, *notes*…", "Compatible avec les apps Bitwarden"),
    }),
]

PAGE = """<!doctype html><html><head><meta charset="utf-8"><style>
*{{margin:0;padding:0;box-sizing:border-box}}
html,body{{width:{W}px;height:{H}px;overflow:hidden}}
body{{background:linear-gradient(160deg,{c1} 0%,{c2} 100%);font-family:-apple-system,"SF Pro Display",system-ui,sans-serif;color:#fff;position:relative}}
.glow{{position:absolute;inset:auto -20% -10% -20%;height:55%;background:radial-gradient(ellipse at center,rgba(255,255,255,.22),transparent 65%)}}
.top{{position:absolute;top:140px;left:0;right:0;text-align:center;padding:0 90px}}
.kicker{{display:inline-block;font-size:42px;font-weight:600;letter-spacing:.5px;padding:12px 32px;border-radius:999px;background:rgba(255,255,255,.16);margin-bottom:40px}}
.sub{{margin-top:40px;font-size:50px;line-height:1.25;font-weight:500;opacity:.88}}
h1{{font-size:{size}px;line-height:1.04;font-weight:800;letter-spacing:-3px}}
h1 em{{font-style:normal;background:#fff;color:{c1};padding:0 18px;border-radius:22px;-webkit-box-decoration-break:clone;box-decoration-break:clone}}
.phone{{position:absolute;left:50%;top:{phone_top}px;width:{pw}px;height:{ph}px;transform:translateX(-50%);border-radius:118px;background:#0B0B0F;padding:22px;box-shadow:0 60px 120px rgba(0,0,0,.35),0 0 0 4px rgba(255,255,255,.18)}}
.phone img{{width:100%;height:100%;border-radius:98px;display:block;object-fit:cover;object-position:top}}
</style></head><body><div class="glow"></div>
<div class="top"><div class="kicker">{kicker}</div><h1>{headline}</h1><div class="sub">{footer}</div></div>
<div class="phone"><img src="data:image/png;base64,{img}"></div>
</body></html>"""


def headline_html(text):
    parts = html.escape(text).split("*")
    out = "".join(f"<em>{p}</em>" if i % 2 else p for i, p in enumerate(parts))
    return out.replace("\n", "<br>")


def main():
    raw, out, lang = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
    for size in SIZES:
        (out / size).mkdir(parents=True, exist_ok=True)
    # Phone frame: the capture's aspect ratio, as large as the layout allows.
    pw = 1060
    ph = round((pw - 44) * H / W) + 44
    phone_top = 830
    with tempfile.TemporaryDirectory() as tmp:
        for n, (shot, (c1, c2), texts) in enumerate(SLIDES, 1):
            kicker, headline, footer = texts[lang]
            longest = max(len(line) for line in headline.replace("*", "").split("\n"))
            size = 150 if longest <= 14 else 128 if longest <= 17 else 112
            img = base64.b64encode((raw / f"{shot}.png").read_bytes()).decode()
            page = Path(tmp) / f"{n}.html"
            page.write_text(PAGE.format(W=W, H=H, c1=c1, c2=c2, kicker=html.escape(kicker),
                                        headline=headline_html(headline), footer=html.escape(footer),
                                        img=img, pw=pw, ph=ph, phone_top=phone_top, size=size))
            name = f"{n:02d}-{shot.split('-', 1)[1]}.png"
            target = out / "6.9in" / name
            subprocess.run([BRAVE, "--headless=new", "--disable-gpu", "--hide-scrollbars",
                            "--force-device-scale-factor=1", f"--window-size={W},{H}",
                            f"--screenshot={target}", page.as_uri()],
                           check=True, capture_output=True)
            w, h = SIZES["6.3in"]
            subprocess.run(["sips", "-z", str(h), str(w), str(target), "--out", str(out / "6.3in" / name)],
                           check=True, capture_output=True)
            print(name)


main()
