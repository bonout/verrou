// Shared by every page (site/build.py); the home page gives the notch's
// words in <script type="application/json" id="notch-scenes">.

// The language switch remembers the reader's choice (the English page's
// <head> sends French browsers to /fr/ until they pick one).
for (const link of document.querySelectorAll("a[hreflang]")) {
  link.addEventListener("click", () => {
    try { localStorage.setItem("lang", link.hreflang); } catch {}
  });
}

const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;

// The notch tells the story: a request, the iPhone, a code.
const notch = document.getElementById("notch");
const words = document.getElementById("notch-scenes");
if (notch && words) {
  const slot = document.getElementById("notch-slot");
  const ring = '<svg class="ring" viewBox="0 0 18 18"><circle class="track" cx="9" cy="9" r="7"/><circle class="bar" cx="9" cy="9" r="7"/></svg>';
  const scenes = JSON.parse(words.textContent).map((scene) => scene.replace("{ring}", ring));
  let i = 0;
  const show = () => {
    slot.innerHTML = scenes[i];
    notch.classList.toggle("open", i !== 0);
  };
  show();
  if (!reduced) {
    setInterval(() => {
      notch.classList.remove("open");
      setTimeout(() => { i = (i + 1) % scenes.length; show(); }, 450);
    }, 2800);
  }
}

// Videos (preload="none", data-play) load and play only while on screen,
// and not at all with reduced motion: the poster stays.
const player = new IntersectionObserver((entries) => {
  for (const entry of entries) {
    if (entry.isIntersecting) entry.target.play().catch(() => {});
    else entry.target.pause();
  }
}, { threshold: 0.25 });
if (!reduced) document.querySelectorAll("video[data-play]").forEach((video) => player.observe(video));

// Sections rise into view; the approval steps light up one by one.
const flow = document.getElementById("flow");
const observer = new IntersectionObserver((entries) => {
  for (const entry of entries) {
    if (!entry.isIntersecting) continue;
    entry.target.classList.add("in");
    if (flow && entry.target === flow) {
      [...flow.children].forEach((bubble, n) => setTimeout(() => {
        bubble.classList.add("on");
        if (n === 2) bubble.classList.add("done");
      }, reduced ? 0 : 500 + n * 900));
    }
    observer.unobserve(entry.target);
  }
}, { threshold: 0.2 });
document.querySelectorAll(".reveal").forEach((el) => observer.observe(el));
