#!/usr/bin/env python3
"""Builds verrou.bonout.com into a folder: every page in English and French.

    python3 site/build.py _site 0.3.1

Each page of site/pages/<lang>/ starts with a comment holding its metadata
(JSON: title, description, optional "schema": "app" or "faq"); the layout
(site/layout.html) wraps it with the navigation, the alternate languages,
the structured data and the footer. Next to the pages: sitemap.xml,
robots.txt (search engines and AI crawlers welcome), llms.txt and
llms-full.txt (llmstxt.org: what an AI assistant should know about Verrou).
The pictures and videos are copied by the Pages workflow.
"""
import html
import json
import re
import shutil
import sys
from datetime import date
from html.parser import HTMLParser
from pathlib import Path

SITE = "https://verrou.bonout.com"
REPO = "https://github.com/bonout/verrou"
LANGS = ("en", "fr")

# Page: its file in pages/<lang>/, then its path in each language.
PAGES = [
    ("index", {"en": "/", "fr": "/fr/"}),
    ("vaultwarden-mac", {"en": "/vaultwarden-mac/", "fr": "/fr/client-vaultwarden-mac/"}),
    ("vaultwarden-iphone", {"en": "/vaultwarden-iphone/", "fr": "/fr/client-vaultwarden-iphone/"}),
    ("ai-agents", {"en": "/ai-agents-secrets/", "fr": "/fr/secrets-agents-ia/"}),
    ("bitwarden-alternative", {"en": "/bitwarden-alternative/", "fr": "/fr/alternative-app-bitwarden/"}),
    ("1password-alternative", {"en": "/1password-alternative/", "fr": "/fr/alternative-1password/"}),
    ("faq", {"en": "/faq/", "fr": "/fr/faq/"}),
]
PATHS = {name: paths for name, paths in PAGES}

WORDS = {
    "en": {
        "mac": "Mac", "iphone": "iPhone", "agents": "AI agents", "compare": "Compare",
        "faq": "FAQ", "download": "Download", "other": "FR", "other_name": "Français",
        "footer": "Open source, GPL-3.0. Not affiliated with Bitwarden.",
        "privacy": "Privacy", "contact": "Contact", "security": "Security",
        "vs_bitwarden": "Verrou vs the Bitwarden app", "vs_1password": "Verrou vs 1Password",
    },
    "fr": {
        "mac": "Mac", "iphone": "iPhone", "agents": "Agents IA", "compare": "Comparer",
        "faq": "FAQ", "download": "Télécharger", "other": "EN", "other_name": "English",
        "footer": "Open source, GPL-3.0. Non affilié à Bitwarden.",
        "privacy": "Confidentialité", "contact": "Contact", "security": "Sécurité",
        "vs_bitwarden": "Verrou ou l'app Bitwarden", "vs_1password": "Verrou ou 1Password",
    },
}


def meta_and_body(path):
    text = path.read_text()
    match = re.match(r"\s*<!--(.*?)-->\s*", text, re.S)
    if not match:
        sys.exit(f"{path}: the page must start with its metadata comment")
    return json.loads(match.group(1)), text[match.end():]


def app_schema(lang, version, description):
    return {
        "@context": "https://schema.org",
        "@type": "SoftwareApplication",
        "name": "Verrou",
        "description": description,
        "applicationCategory": "SecurityApplication",
        "operatingSystem": "macOS 15 or later, iOS 17 or later",
        "softwareVersion": version,
        "offers": {"@type": "Offer", "price": "0", "priceCurrency": "EUR"},
        "license": "https://www.gnu.org/licenses/gpl-3.0.html",
        "downloadUrl": f"{REPO}/releases/download/v{version}/Verrou-{version}-macos.dmg",
        "url": SITE + PATHS["index"][lang],
        "image": f"{SITE}/media/{lang}/mac.png",
        "codeRepository": REPO,
        "inLanguage": lang,
        "publisher": {"@type": "Organization", "name": "Bonout", "email": "contact@bonout.com"},
    }


def faq_schema(body):
    """FAQPage from the <h3> questions and the paragraphs under them."""
    entries = []
    for question, answer in re.findall(r"<h3>(.*?)</h3>(.*?)(?=<h3>|</section>)", body, re.S):
        entries.append({
            "@type": "Question",
            "name": text_of(question),
            "acceptedAnswer": {"@type": "Answer", "text": text_of(answer)},
        })
    if not entries:
        sys.exit("faq: no question found")
    return {"@context": "https://schema.org", "@type": "FAQPage", "mainEntity": entries}


class _Text(HTMLParser):
    """Visible text of a fragment, one block per line (for llms-full.txt)."""
    BLOCKS = {"p", "li", "h1", "h2", "h3", "pre", "tr", "div", "section", "br"}
    SKIP = {"script", "style", "svg"}

    def __init__(self):
        super().__init__()
        self.out, self.skip = [], 0

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP:
            self.skip += 1
        elif tag in ("h1", "h2"):
            self.out.append("\n\n## " if tag == "h2" else "\n\n# ")
        elif tag == "h3":
            self.out.append("\n\n### ")
        elif tag == "li":
            self.out.append("\n- ")
        elif tag in ("td", "th"):
            self.out.append(" | ")
        elif tag in self.BLOCKS:
            self.out.append("\n")

    def handle_endtag(self, tag):
        if tag in self.SKIP:
            self.skip -= 1
        elif tag in self.BLOCKS:
            self.out.append("\n")

    def handle_data(self, data):
        if not self.skip:
            self.out.append(data)


def text_of(fragment):
    parser = _Text()
    parser.feed(fragment)
    text = "".join(parser.out)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r" *\n *", "\n", text)
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def build(out, version):
    root = Path(__file__).resolve().parent
    layout = (root / "layout.html").read_text()
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    for item in ("style.css", "site.js", "CNAME", ".nojekyll", "img"):
        source = root / item
        if source.is_dir():
            shutil.copytree(source, out / item)
        elif source.exists():
            shutil.copy(source, out / item)

    full_text = []
    for name, paths in PAGES:
        for lang in LANGS:
            other = "fr" if lang == "en" else "en"
            meta, body = meta_and_body(root / "pages" / lang / f"{name}.html")
            words = WORDS[lang]
            schema = None
            if meta.get("schema") == "app":
                schema = app_schema(lang, version, meta["description"])
            elif meta.get("schema") == "faq":
                schema = faq_schema(body)
            # French browsers landing on an English page get its French
            # version, until their reader picks a language with the switch.
            redirect = ""
            if lang == "en":
                redirect = ("<script>try{const p=((navigator.languages||[navigator.language])[0]||'')"
                            ".toLowerCase();if(!localStorage.getItem('lang')&&p.startsWith('fr'))"
                            f"location.replace({json.dumps(paths['fr'])}+location.hash)}}catch{{}}</script>")
            values = {
                "lang": lang,
                "title": html.escape(meta["title"]),
                "description": html.escape(meta["description"]),
                "canonical": SITE + paths[lang],
                "alternate_en": SITE + paths["en"],
                "alternate_fr": SITE + paths["fr"],
                "og_image": f"{SITE}/img/og-{lang}.png",
                "og_locale": "en_US" if lang == "en" else "fr_FR",
                "schema": (f'<script type="application/ld+json">{json.dumps(schema, ensure_ascii=False)}</script>'
                           if schema else ""),
                "redirect": redirect,
                "home": PATHS["index"][lang],
                "mac": PATHS["vaultwarden-mac"][lang],
                "iphone": PATHS["vaultwarden-iphone"][lang],
                "agents": PATHS["ai-agents"][lang],
                "bitwarden": PATHS["bitwarden-alternative"][lang],
                "onepassword": PATHS["1password-alternative"][lang],
                "faq": PATHS["faq"][lang],
                "other_href": paths[other],
                "other_lang": other,
                "body": body,
                **{f"w_{key}": value for key, value in words.items()},
            }
            page = re.sub(r"\{\{(\w+)\}\}", lambda m: values[m.group(1)] if m.group(1) in values else m.group(0), layout)
            page = page.replace("{{version}}", version)
            left = re.findall(r"\{\{\w+\}\}", page)
            if left:
                sys.exit(f"{lang}/{name}: unfilled {sorted(set(left))}")
            target = out / paths[lang].lstrip("/") / "index.html"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(page)
            if lang == "en":
                full_text.append(f"Page: {SITE}{paths[lang]}\n\n{text_of(body.replace('{{version}}', version))}")

    today = date.today().isoformat()
    urls = []
    for _, paths in PAGES:
        for lang in LANGS:
            links = "".join(f'<xhtml:link rel="alternate" hreflang="{other}" href="{SITE}{paths[other]}"/>'
                            for other in LANGS)
            links += f'<xhtml:link rel="alternate" hreflang="x-default" href="{SITE}{paths["en"]}"/>'
            urls.append(f"<url><loc>{SITE}{paths[lang]}</loc><lastmod>{today}</lastmod>{links}</url>")
    (out / "sitemap.xml").write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">\n'
        + "\n".join(urls) + "\n</urlset>\n")

    # Search engines and AI assistants (their search and their answers) are
    # all welcome: the site only describes an open source app.
    agents = ["GPTBot", "OAI-SearchBot", "ChatGPT-User", "ClaudeBot", "Claude-SearchBot", "Claude-User",
              "PerplexityBot", "Perplexity-User", "Google-Extended", "Applebot-Extended", "CCBot", "*"]
    (out / "robots.txt").write_text(
        "".join(f"User-agent: {agent}\nAllow: /\n\n" for agent in agents) + f"Sitemap: {SITE}/sitemap.xml\n")

    llms = (root / "llms.txt").read_text().replace("{{version}}", version)
    (out / "llms.txt").write_text(llms)
    (out / "llms-full.txt").write_text(llms.rstrip() + "\n\n---\n\n" + "\n\n---\n\n".join(full_text) + "\n")


if __name__ == "__main__":
    if len(sys.argv) != 3 or not re.fullmatch(r"\d+\.\d+\.\d+", sys.argv[2]):
        sys.exit("usage: build.py <output folder> <version x.y.z>")
    build(Path(sys.argv[1]), sys.argv[2])
