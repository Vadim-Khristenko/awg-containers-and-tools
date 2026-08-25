/*
 * The verdict is the page loading at all: the name resolves only through the
 * tunnel's resolver, the address answers only inside the tunnel. Everything
 * below fills in the details, and both of them come from this same host over
 * the tunnel — the IP from a CGI that echoes what the socket sees, the speed
 * from timing a download of a file served right here. Nothing leaves.
 */
"use strict";

const I18N = {
    ru: {
        verdict: "Да",
        verdictSub: "эта страница существует только внутри туннеля — раз она открылась, вы под VPN",
        kIp: "Ваш адрес в туннеле",
        kName: "DNS-имя",
        kSpeed: "Скорость через туннель",
        speedIdle: "не измерена",
        speedRun: "измеряем…",
        speedBtn: "Измерить скорость",
        speedAgain: "Измерить снова",
        ipFail: "недоступен",
        speedFail: "не удалось измерить",
        foot: "Страница отвечает только изнутри туннеля и никуда не обращается извне: ни счётчиков, ни сторонних спидтестов, ни запросов, которые могли бы выдать ваш реальный адрес.",
    },
    en: {
        verdict: "Yes",
        verdictSub: "this page exists only inside the tunnel — if it opened at all, you are under the VPN",
        kIp: "Your tunnel address",
        kName: "DNS name",
        kSpeed: "Speed through the tunnel",
        speedIdle: "not measured",
        speedRun: "measuring…",
        speedBtn: "Measure speed",
        speedAgain: "Measure again",
        ipFail: "unavailable",
        speedFail: "could not measure",
        foot: "This page answers only from inside the tunnel and reaches nowhere else: no counters, no third-party speed tests, no request that could reveal your real address.",
    },
};

const $ = (id) => document.getElementById(id);
let lang = "ru";

/*
 * The browser's language picks the default, and the choice sticks in
 * localStorage — a tunnel is revisited, and nobody wants to flip the switch
 * every time.
 */
function detectLang() {
    const saved = localStorage.getItem("amiunder-lang");
    if (saved === "ru" || saved === "en") return saved;
    return (navigator.language || "ru").toLowerCase().startsWith("en") ? "en" : "ru";
}

function applyLang() {
    const t = I18N[lang];
    document.documentElement.lang = lang;
    $("verdict").textContent = t.verdict;
    $("verdict-sub").textContent = t.verdictSub;
    $("k-ip").textContent = t.kIp;
    $("k-name").textContent = t.kName;
    $("k-speed").textContent = t.kSpeed;
    $("foot").textContent = t.foot;
    $("lang-ru").classList.toggle("on", lang === "ru");
    $("lang-en").classList.toggle("on", lang === "en");
    const speed = $("speed");
    if (speed.classList.contains("pending")) speed.textContent = t.speedIdle;
    const btn = $("go");
    if (!btn.disabled) btn.textContent = t.speedBtn;
    localStorage.setItem("amiunder-lang", lang);
}

/* The address the tunnel sees, echoed by the CGI on this same host. */
async function loadIp() {
    const el = $("tunnel-ip");
    try {
        const r = await fetch("/cgi-bin/whoami", { cache: "no-store" });
        if (!r.ok) throw new Error(r.status);
        el.textContent = (await r.text()).trim();
        el.classList.remove("pending");
    } catch {
        el.textContent = I18N[lang].ipFail;
    }
}

/*
 * Download the payload from this host and time it. One stream, honest
 * numbers: this measures the tunnel as the page's visitor experiences it,
 * not a parallel-connection figure a speed-test site would advertise.
 */
async function measureSpeed() {
    const t = I18N[lang];
    const btn = $("go"), speed = $("speed"), meter = $("meter"), fill = $("meter-fill");
    btn.disabled = true;
    btn.textContent = t.speedRun;
    speed.textContent = t.speedRun;
    speed.classList.remove("pending");
    meter.style.display = "block";

    const BYTES = 8 * 1024 * 1024;
    try {
        const r = await fetch("/speedtest.bin?b=" + Date.now(), { cache: "no-store" });
        if (!r.ok || !r.body) throw new Error("no body");
        const reader = r.body.getReader();
        let got = 0;
        const t0 = performance.now();
        for (;;) {
            const { done, value } = await reader.read();
            if (done) break;
            got += value.length;
            const frac = Math.min(1, got / BYTES);
            fill.style.width = (frac * 100).toFixed(1) + "%";
            const secs = (performance.now() - t0) / 1000;
            if (secs > 0.2) {
                speed.textContent = ((got * 8) / secs / 1e6).toFixed(1) + " Mbps";
            }
        }
        const secs = (performance.now() - t0) / 1000;
        speed.textContent = ((got * 8) / secs / 1e6).toFixed(1) + " Mbps";
    } catch {
        speed.textContent = t.speedFail;
    }
    fill.style.width = "100%";
    setTimeout(() => { meter.style.display = "none"; fill.style.width = "0%"; }, 600);
    btn.disabled = false;
    btn.textContent = t.speedAgain;
}

$("lang-ru").addEventListener("click", () => { lang = "ru"; applyLang(); });
$("lang-en").addEventListener("click", () => { lang = "en"; applyLang(); });
$("go").addEventListener("click", measureSpeed);

lang = detectLang();
applyLang();
loadIp();
