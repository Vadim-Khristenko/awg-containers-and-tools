/*
 * The tunnel's own pages, one script for all of them. Which page is drawn is
 * decided by the name the browser opened: amiunder.vpn, dns.vpn, speed.vpn,
 * mtu.vpn, node.vpn, or any <nonce>.leak.vpn. Opened by address, it is the
 * amiunder page.
 *
 * Every name resolves only through the tunnel's resolver and the address
 * answers only inside the tunnel, so the page loading at all is the first
 * answer. Everything else is fetched from this same host over the tunnel:
 * the address the socket saw, the resolver's public counters, the node's
 * facts, files to time. Nothing leaves.
 *
 * Text is set with textContent only. What a CGI answers is data, and it is
 * never parsed as markup.
 */
"use strict";

const PAGES = ["amiunder", "dns", "speed", "mtu", "leak", "node"];

const I18N = {
    ru: {
        nav: { amiunder: "под VPN?", dns: "DNS", speed: "скорость", mtu: "MTU", leak: "утечки", node: "узел" },
        pending: "…",
        unavailable: "недоступно",
        yes: "да",
        no: "нет",
        on: "включено",
        off: "выключено",
        ms: "мс",
        ago: (s) => `${dur(s, "ru")} назад`,
        units: { d: "д", h: "ч", m: "мин", s: "с" },
        amiunder: {
            title: "вы под VPN?",
            verdict: "Да",
            sub: "эта страница существует только внутри туннеля: раз она открылась, вы под VPN",
            ip: "Адрес, который видит страница",
            name: "Имя страницы",
            speed: "Скорость через туннель",
            speedIdle: "не измерена",
            speedBtn: "Измерить скорость",
            more: "Остальные страницы туннеля вверху: DNS, скорость, MTU, утечки и сам узел.",
            foot: "Страница отвечает только изнутри туннеля и никуда не обращается извне: ни счётчиков, ни сторонних спидтестов, ни запросов, которые могли бы выдать ваш реальный адрес.",
        },
        dns: {
            title: "резолвер туннеля",
            sub: "резолвер, которому ваш клиент шлёт запросы через туннель",
            mode: { recursive: "Рекурсия", forward: "DoT", auto: "Авто" },
            modeSub: { recursive: "спрашивает корневые серверы сам, без посредника", forward: "пересылает запросы по DoT, зашифрованно", auto: "выбирает режим при старте" },
            kBlocked: "Имён в блок-листе",
            kAllowed: "Разрешено поверх списков",
            kQueries: "Запросов",
            kCache: "Из кэша",
            kNx: "Ответов «нет такого имени»",
            kFail: "Ошибок резолва",
            kRecursion: "Среднее время ответа",
            kUp: "Работает",
            kCanary: "Канарейка DoH",
            kChain: "Резолверов в цепочке",
            kChainFurther: "Ответили дальше по цепочке",
            kZones: "Пересылаемых зон",
            kUpdated: "Обновлено",
            safe: "безопасный режим: файлы оператора не загрузились",
            noState: "Счётчики недоступны: том резолвера awg-dns-public не подключён к странице.",
            ask: "Спросить резолвер",
            askPh: "example.com",
            askBtn: "Спросить",
            ok: "отвечает",
            nx: "нет такого имени или заблокировано",
            fail: "резолвер не ответил",
            refused: "это не имя",
            foot: "Страница показывает только количества: ни одного имени, которое кто-то спрашивал или которое стоит в списке.",
        },
        speed: {
            title: "скорость туннеля",
            sub: "один поток до этого узла и обратно, как его видит ваш браузер",
            head: "Не измерено",
            kDown: "Загрузка",
            kUp: "Отдача",
            kPing: "Задержка",
            kJitter: "Разброс задержки",
            idle: "не измерено",
            run: "измеряем…",
            fail: "не удалось",
            btn: "Измерить",
            again: "Измерить снова",
            foot: "Сервер в том же туннеле, что и страница: это скорость туннеля, а не вашего провайдера до случайного сервера спидтеста.",
        },
        mtu: {
            title: "проверка MTU",
            sub: "проходят ли большие пакеты через туннель",
            idle: "Не проверено",
            clean: "Пакеты проходят",
            lossy: "Большие пакеты теряются",
            broken: "Туннель не отвечает",
            kMtu: "MTU узла",
            kDown: (s) => `Загрузка ${s}`,
            kUp: (s) => `Отдача ${s}`,
            okIn: (ms) => `${ms} мс`,
            lost: "не дошло",
            btn: "Проверить",
            explain: "Если мелкие ответы доходят, а крупные застревают, где-то на пути пакеты больше MTU выбрасываются без сообщения об этом. Страницы тогда открываются наполовину, а загрузки висят.",
            advice: "Уменьшите MTU в конфиге клиента: 1280 подходит почти везде, его же использует AWG 3.1. На узле это делает awg-mtu.",
            foot: "Размеры от 1 КБ до 1 МБ в обе стороны: первый размер, который не дошёл, показывает, где начинается потеря.",
        },
        leak: {
            title: "проверка утечек",
            sub: "куда ваш браузер отправляет DNS-запросы",
            clean: "Утечки DNS нет",
            cleanSub: "новое имя, которое знает только резолвер туннеля, нашлось: браузер спрашивает его",
            leak: "Браузер ищет имена сам",
            leakSub: "имя, которое знает только резолвер туннеля, не нашлось: браузер спрашивает другой резолвер (часто DoH) мимо туннеля",
            kName: "Свежее имя",
            kIp: "Адрес, который видит страница",
            found: "нашлось",
            missing: "не нашлось",
            again: "Проверить снова",
            note: "Страница видит только браузер. Утечку всей системы, IPv6 мимо туннеля и чужой резолвер на месте туннельного проверяет awg-tool under на этой машине и awg-leak на узле.",
            foot: "Каждая проверка спрашивает имя, которого раньше не было, так что ответ из чьего-то кэша её не подделает.",
        },
        node: {
            title: "узел",
            sub: "сервер AmneziaWG, через который вы подключены",
            unknown: "Узел не представился",
            kProto: "Протокол",
            kDaemon: "Демон",
            kMtu: "MTU",
            kUp: "Работает",
            kPeers: "Пиров с именами",
            pages: "Страницы туннеля",
            desc: {
                amiunder: "под VPN вы или нет",
                dns: "резолвер туннеля и его счётчики",
                speed: "скорость через туннель",
                mtu: "проходят ли большие пакеты",
                leak: "куда уходят DNS-запросы браузера",
                node: "этот узел",
            },
            foot: "Узел сообщает о себе только то, что и так есть в конфиге клиента. Имена других пиров страница не показывает.",
        },
    },
    en: {
        nav: { amiunder: "under VPN?", dns: "DNS", speed: "speed", mtu: "MTU", leak: "leaks", node: "node" },
        pending: "…",
        unavailable: "unavailable",
        yes: "yes",
        no: "no",
        on: "on",
        off: "off",
        ms: "ms",
        ago: (s) => `${dur(s, "en")} ago`,
        units: { d: "d", h: "h", m: "min", s: "s" },
        amiunder: {
            title: "are you under the VPN?",
            verdict: "Yes",
            sub: "this page exists only inside the tunnel: if it opened at all, you are under the VPN",
            ip: "Address the page sees",
            name: "Page name",
            speed: "Speed through the tunnel",
            speedIdle: "not measured",
            speedBtn: "Measure speed",
            more: "The tunnel's other pages are above: DNS, speed, MTU, leaks and the node itself.",
            foot: "This page answers only from inside the tunnel and reaches nowhere else: no counters, no third-party speed tests, no request that could reveal your real address.",
        },
        dns: {
            title: "the tunnel's resolver",
            sub: "the resolver your client sends its queries to, through the tunnel",
            mode: { recursive: "Recursive", forward: "DoT", auto: "Auto" },
            modeSub: { recursive: "asks the root servers itself, no middleman", forward: "forwards queries over DoT, encrypted", auto: "picks a mode at start" },
            kBlocked: "Names on the blocklist",
            kAllowed: "Allowed over the lists",
            kQueries: "Queries",
            kCache: "From cache",
            kNx: "\"No such name\" answers",
            kFail: "Failed lookups",
            kRecursion: "Average answer time",
            kUp: "Up for",
            kCanary: "DoH canary",
            kChain: "Resolvers in the chain",
            kChainFurther: "Answered further down the chain",
            kZones: "Forwarded zones",
            kUpdated: "Updated",
            safe: "safe mode: the operator's files did not load",
            noState: "Counters unavailable: the resolver's awg-dns-public volume is not mounted for this page.",
            ask: "Ask the resolver",
            askPh: "example.com",
            askBtn: "Ask",
            ok: "answers",
            nx: "no such name, or blocked",
            fail: "the resolver did not answer",
            refused: "that is not a name",
            foot: "The page shows counts only: not one name anybody asked for or any list holds.",
        },
        speed: {
            title: "tunnel speed",
            sub: "one stream to this node and back, as your browser sees it",
            head: "Not measured",
            kDown: "Download",
            kUp: "Upload",
            kPing: "Latency",
            kJitter: "Jitter",
            idle: "not measured",
            run: "measuring…",
            fail: "failed",
            btn: "Measure",
            again: "Measure again",
            foot: "The server is inside the same tunnel as the page: this is the tunnel's speed, not your provider's to some speed-test server.",
        },
        mtu: {
            title: "MTU check",
            sub: "whether large packets make it through the tunnel",
            idle: "Not checked",
            clean: "Packets get through",
            lossy: "Large packets are lost",
            broken: "The tunnel does not answer",
            kMtu: "Node MTU",
            kDown: (s) => `Download ${s}`,
            kUp: (s) => `Upload ${s}`,
            okIn: (ms) => `${ms} ms`,
            lost: "lost",
            btn: "Check",
            explain: "When small answers arrive and large ones stall, something on the path drops packets over its MTU without saying so. Pages then load halfway and downloads hang.",
            advice: "Lower the MTU in the client config: 1280 works nearly everywhere, and it is what AWG 3.1 uses. On the node, awg-mtu does this.",
            foot: "Sizes from 1 KB to 1 MB both ways: the first size that never arrives shows where the loss starts.",
        },
        leak: {
            title: "leak check",
            sub: "where your browser sends its DNS queries",
            clean: "No DNS leak",
            cleanSub: "a new name only the tunnel's resolver knows was found: the browser asks it",
            leak: "The browser resolves names itself",
            leakSub: "a name only the tunnel's resolver knows was not found: the browser asks another resolver (often DoH) around the tunnel",
            kName: "Fresh name",
            kIp: "Address the page sees",
            found: "found",
            missing: "not found",
            again: "Check again",
            note: "A page can see only the browser. A system-wide leak, IPv6 around the tunnel or an impostor at the tunnel resolver's address are what awg-tool under checks on this machine, and awg-leak on the node.",
            foot: "Every check asks for a name that did not exist before, so an answer from somebody's cache cannot fake it.",
        },
        node: {
            title: "node",
            sub: "the AmneziaWG server you are connected through",
            unknown: "The node did not introduce itself",
            kProto: "Protocol",
            kDaemon: "Daemon",
            kMtu: "MTU",
            kUp: "Up for",
            kPeers: "Named peers",
            pages: "The tunnel's pages",
            desc: {
                amiunder: "whether you are under the VPN",
                dns: "the tunnel's resolver and its counters",
                speed: "speed through the tunnel",
                mtu: "whether large packets get through",
                leak: "where the browser's DNS queries go",
                node: "this node",
            },
            foot: "The node tells only what a client's config already says. The page never shows other peers' names.",
        },
    },
};

const $ = (id) => document.getElementById(id);
let lang = "ru";
const T = () => I18N[lang];

function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = text;
    return e;
}

/* One key/value row. `state` is "pending", "bad" or nothing. */
function row(k, v, state) {
    const r = el("div", "row");
    r.append(el("span", "k", k), el("span", "v" + (state ? " " + state : ""), v));
    return r;
}

function rows(list) {
    const box = el("div", "rows");
    for (const r of list) if (r) box.append(r);
    return box;
}

function dur(secs, l) {
    const u = I18N[l || lang].units;
    secs = Math.max(0, Math.floor(secs));
    const d = Math.floor(secs / 86400), h = Math.floor((secs % 86400) / 3600), m = Math.floor((secs % 3600) / 60);
    if (d) return `${d} ${u.d} ${h} ${u.h}`;
    if (h) return `${h} ${u.h} ${m} ${u.m}`;
    if (m) return `${m} ${u.m}`;
    return `${secs} ${u.s}`;
}

function mbps(bytes, ms) {
    return ((bytes * 8) / (ms / 1000) / 1e6).toFixed(1) + " Mbps";
}

/* fetch with a deadline, no cache. Rejects on timeout and on a non-2xx. */
async function get(url, ms, opts) {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), ms || 6000);
    try {
        const r = await fetch(url, Object.assign({ cache: "no-store", signal: ctl.signal }, opts || {}));
        if (r.type !== "opaque" && !r.ok) throw new Error(String(r.status));
        return r;
    } finally {
        clearTimeout(timer);
    }
}

/* key=value lines; a key that repeats collects into an array. */
function kv(text) {
    const out = {};
    for (const line of text.split("\n")) {
        const i = line.indexOf("=");
        if (i < 1) continue;
        const k = line.slice(0, i).trim(), v = line.slice(i + 1).trim();
        if (k in out) out[k] = [].concat(out[k], v);
        else out[k] = v;
    }
    return out;
}

/* Queries the chain's first resolver did not answer and a later one did. */
function further(d) {
    let n = 0;
    for (let i = 1; i < (num(d["chain.upstreams"]) || 0); i++) n += num(d["chain." + i + ".answered"]) || 0;
    return n;
}

function num(v) {
    const n = Number(v);
    return Number.isFinite(n) ? n : null;
}

/* ── state shared by the pages ─────────────────────────────────────────── */

const S = {
    ip: null,          // what whoami says, or false when it failed
    node: null,        // kv of /cgi-bin/node, or false
    dns: null,         // kv of /state/dns.txt, or false
    answer: null,      // last lookup on the dns page
    speed: { running: false },
    mtu: { running: false, results: null },
    leak: { running: false, nonce: null, found: null },
};

async function loadIp() {
    try {
        S.ip = (await (await get("/cgi-bin/whoami")).text()).trim() || false;
    } catch {
        S.ip = false;
    }
    draw();
}

async function loadNode() {
    try {
        const n = kv(await (await get("/cgi-bin/node")).text());
        S.node = n.protocol || n.daemon ? n : false;
    } catch {
        S.node = false;
    }
    draw();
}

async function loadDns() {
    try {
        S.dns = kv(await (await get("/state/dns.txt")).text());
    } catch {
        S.dns = false;
    }
    draw();
}

/*
 * Download a file, reporting progress; resolves to {bytes, ms}. The deadline
 * runs until the last byte, not only until the headers: a path that loses
 * large packets answers at once and then stalls in the body.
 */
async function download(url, onProgress, ms) {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), ms || 60000);
    try {
        const t0 = performance.now();
        const r = await fetch(url + (url.includes("?") ? "&" : "?") + "b=" + Date.now(), { cache: "no-store", signal: ctl.signal });
        if (!r.ok || !r.body) throw new Error(String(r.status));
        const reader = r.body.getReader();
        let got = 0;
        for (;;) {
            const { done, value } = await reader.read();
            if (done) break;
            got += value.length;
            if (onProgress) onProgress(got, performance.now() - t0);
        }
        return { bytes: got, ms: performance.now() - t0 };
    } finally {
        clearTimeout(timer);
    }
}

/* Random bytes, so nothing on the path can compress them. */
function payload(n) {
    const buf = new Uint8Array(n);
    for (let i = 0; i < n; i += 65536) crypto.getRandomValues(buf.subarray(i, Math.min(n, i + 65536)));
    return buf;
}

/* Upload to the sink; resolves to {bytes, ms} once it says it read them all. */
async function upload(n, ms) {
    const body = payload(n);
    const t0 = performance.now();
    const r = await get("/cgi-bin/sink", ms || 60000, { method: "POST", body, headers: { "Content-Type": "application/octet-stream" } });
    const said = Number((await r.text()).trim());
    if (said !== n) throw new Error("short");
    return { bytes: n, ms: performance.now() - t0 };
}

/* ── pages ─────────────────────────────────────────────────────────────── */

function verdict(text, sub, bad) {
    const frag = document.createDocumentFragment();
    frag.append(el("div", "verdict" + (bad ? " bad" : ""), text), el("div", "verdict-sub", sub));
    return frag;
}

function ipRow(label) {
    const t = T();
    if (S.ip === null) return row(label, t.pending, "pending");
    if (S.ip === false) return row(label, t.unavailable, "bad");
    return row(label, S.ip);
}

function button(text, onClick, disabled) {
    const b = el("button", "btn btn--primary wide-btn", text);
    b.type = "button";
    b.disabled = !!disabled;
    b.addEventListener("click", onClick);
    return b;
}

function meter(frac) {
    const m = el("div", "meter");
    const i = el("i");
    i.style.width = (Math.max(0, Math.min(1, frac)) * 100).toFixed(1) + "%";
    m.append(i);
    return m;
}

const page = {
    amiunder(root) {
        const t = T().amiunder;
        const sp = S.speed;
        root.append(
            verdict(t.verdict, t.sub),
            rows([
                ipRow(t.ip),
                row(t.name, HOST_IS_NAME ? location.hostname : "amiunder.vpn"),
                row(t.speed, sp.down || (sp.running ? T().speed.run : t.speedIdle), sp.down ? null : "pending"),
            ]),
            button(sp.running ? T().speed.run : t.speedBtn, () => runSpeed(true), sp.running),
        );
        if (sp.running) root.append(meter(sp.frac || 0));
        root.append(el("p", "note", t.more));
    },

    dns(root) {
        const t = T().dns;
        const d = S.dns;
        if (d === null) {
            root.append(verdict(T().pending, t.sub, true));
        } else if (d === false) {
            root.append(verdict(T().unavailable, t.sub, true), el("p", "note", t.noState));
        } else {
            const mode = d.mode in t.mode ? d.mode : "auto";
            root.append(verdict(t.mode[mode], d.safe === "1" ? t.safe : t.modeSub[mode], d.safe === "1"));
            const q = num(d["total.num.queries"]);
            const hits = num(d["total.num.cachehits"]);
            const nx = num(d["num.answer.rcode.NXDOMAIN"]);
            const fail = num(d["num.answer.rcode.SERVFAIL"]);
            const rec = num(d["total.recursion.time.avg"]);
            const up = num(d["time.up"]);
            const upd = num(d.updated);
            const share = (n) => (q ? Math.round((n * 100) / q) + "%" : "0%");
            const canary = String(d.canary || "").split(/\s+/).filter((c) => c && c !== "none");
            root.append(rows([
                row(t.kBlocked, String(num(d.blocked) ?? 0)),
                row(t.kAllowed, String(num(d.allowed) ?? 0)),
                q !== null ? row(t.kQueries, String(q)) : null,
                hits !== null ? row(t.kCache, share(hits)) : null,
                nx !== null ? row(t.kNx, share(nx)) : null,
                fail !== null ? row(t.kFail, share(fail), fail ? "bad" : null) : null,
                rec !== null && rec > 0 ? row(t.kRecursion, Math.round(rec * 1000) + " " + T().ms) : null,
                up !== null ? row(t.kUp, dur(up)) : null,
                row(t.kCanary, canary.length ? canary.join(", ") : T().off),
                num(d.zones) ? row(t.kZones, String(num(d.zones))) : null,
                num(d["chain.upstreams"]) ? row(t.kChain, String(num(d["chain.upstreams"]))) : null,
                num(d["chain.upstreams"]) ? row(t.kChainFurther, String(further(d))) : null,
                upd !== null ? row(t.kUpdated, T().ago(Date.now() / 1000 - upd)) : null,
            ]));
        }

        root.append(el("div", "note", t.ask));
        const form = el("form", "ask");
        const input = el("input");
        input.type = "text";
        input.placeholder = t.askPh;
        input.autocomplete = "off";
        input.spellcheck = false;
        input.value = S.answer ? S.answer.asked : "";
        const go = el("button", "btn btn--primary", t.askBtn);
        go.type = "submit";
        form.append(input, go);
        form.addEventListener("submit", (e) => {
            e.preventDefault();
            lookup(input.value.trim());
        });
        root.append(form);
        const a = S.answer;
        if (a) {
            const list = [];
            if (a.pending) list.push(row(a.asked, T().pending, "pending"));
            else if (a.status === "ok") {
                for (const addr of [].concat(a.address || [])) list.push(row(a.asked, addr));
            } else {
                const say = { nxdomain: t.nx, refused: t.refused }[a.status] || t.fail;
                list.push(row(a.asked, say, "bad"));
            }
            root.append(rows(list));
        }
    },

    speed(root) {
        const t = T().speed;
        const sp = S.speed;
        root.append(
            verdict(sp.down && !sp.running ? sp.down : sp.running ? t.run : t.head, t.sub, !sp.down || sp.running),
            rows([
                row(t.kDown, sp.down || (sp.running ? t.run : t.idle), sp.down ? null : "pending"),
                row(t.kUp, sp.up || (sp.running ? t.run : t.idle), sp.up ? null : "pending"),
                row(t.kPing, sp.ping || (sp.running ? t.run : t.idle), sp.ping ? null : "pending"),
                row(t.kJitter, sp.jitter || (sp.running ? t.run : t.idle), sp.jitter ? null : "pending"),
            ]),
            button(sp.running ? t.run : sp.done ? t.again : t.btn, () => runSpeed(false), sp.running),
        );
        if (sp.running) root.append(meter(sp.frac || 0));
    },

    mtu(root) {
        const t = T().mtu;
        const m = S.mtu;
        let head = t.idle, bad = true;
        if (m.results) {
            const all = m.results.every((r) => r.ok !== false);
            const any = m.results.some((r) => r.ok);
            if (m.running) head = T().pending;
            else if (all) { head = t.clean; bad = false; }
            else if (any) head = t.lossy;
            else head = t.broken;
        }
        root.append(verdict(head, t.sub, bad));
        const list = [];
        const n = S.node;
        if (n && n.mtu) list.push(row(t.kMtu, n.mtu));
        for (const r of m.results || []) {
            const label = r.dir === "down" ? t.kDown(r.label) : t.kUp(r.label);
            if (r.ok === undefined) list.push(row(label, T().pending, "pending"));
            else if (r.ok) list.push(row(label, t.okIn(Math.round(r.ms))));
            else list.push(row(label, t.lost, "bad"));
        }
        root.append(rows(list));
        root.append(button(m.running ? T().pending : t.btn, runMtu, m.running));
        root.append(el("p", "note", t.explain));
        if (m.results && !m.running && head === t.lossy) root.append(el("p", "note", t.advice));
    },

    leak(root) {
        const t = T().leak;
        const l = S.leak;
        if (l.found === null) root.append(verdict(T().pending, t.sub, true));
        else if (l.found) root.append(verdict(t.clean, t.cleanSub));
        else root.append(verdict(t.leak, t.leakSub, true));
        root.append(rows([
            l.nonce ? row(t.kName, l.found === null ? T().pending : l.found ? t.found : t.missing, l.found === null ? "pending" : l.found ? null : "bad") : null,
            l.nonce ? row("", l.nonce + ".leak.vpn", "pending") : null,
            ipRow(t.kIp),
        ]));
        root.append(button(l.running ? T().pending : t.again, runLeak, l.running));
        root.append(el("p", "note", t.note));
    },

    node(root) {
        const t = T().node;
        const n = S.node;
        if (n === null) root.append(verdict(T().pending, t.sub, true));
        else if (n === false) root.append(verdict(t.unknown, t.sub, true));
        else root.append(verdict(n.protocol ? "AWG " + n.protocol : "AWG", t.sub));
        if (n) {
            const started = num(n.started), now = num(n.now);
            root.append(rows([
                n.protocol ? row(t.kProto, n.protocol) : null,
                n.daemon ? row(t.kDaemon, n.daemon) : null,
                n.mtu ? row(t.kMtu, n.mtu) : null,
                started !== null && now !== null ? row(t.kUp, dur(now - started)) : null,
                n.peers !== undefined ? row(t.kPeers, n.peers) : null,
            ]));
        }
        root.append(el("div", "note", t.pages));
        const list = el("div", "rows");
        for (const p of PAGES) {
            const a = el("a", "row");
            a.href = pageUrl(p);
            a.append(el("span", "k", p + ".vpn"), el("span", "v", t.desc[p]));
            list.append(a);
        }
        root.append(list);
    },
};

/* ── the measurements ──────────────────────────────────────────────────── */

async function runSpeed(downOnly) {
    const sp = S.speed;
    if (sp.running) return;
    sp.running = true;
    sp.frac = 0;
    draw();
    const fail = T().speed.fail;
    if (!downOnly) {
        // Latency first, on an idle tunnel: the same tiny request ten times.
        try {
            const times = [];
            for (let i = 0; i < 10; i++) {
                const t0 = performance.now();
                await (await get("/cgi-bin/whoami", 5000)).text();
                times.push(performance.now() - t0);
            }
            times.sort((a, b) => a - b);
            const median = times[Math.floor(times.length / 2)];
            const jitter = times.slice(1).reduce((s, v, i) => s + Math.abs(v - times[i]), 0) / (times.length - 1);
            sp.ping = `${Math.round(median)} ${T().ms} (min ${Math.round(times[0])})`;
            sp.jitter = `${Math.round(jitter)} ${T().ms}`;
        } catch {
            sp.ping = fail;
        }
        draw();
    }
    try {
        const BYTES = 8 * 1024 * 1024;
        const r = await download("/speedtest.bin", (got, ms) => {
            sp.frac = (downOnly ? 1 : 0.5) * (got / BYTES);
            if (ms > 200) sp.down = mbps(got, ms);
            drawSoon();
        });
        sp.down = mbps(r.bytes, r.ms);
    } catch {
        sp.down = fail;
    }
    if (!downOnly) {
        sp.frac = 0.6;
        draw();
        try {
            const r = await upload(8 * 1024 * 1024);
            sp.up = mbps(r.bytes, r.ms);
        } catch {
            sp.up = fail;
        }
    }
    sp.running = false;
    sp.done = true;
    draw();
}

// name, bytes, label, deadline: generous enough for a slow link, short enough
// that a stall reads as a loss rather than as patience.
const MTU_SIZES = [["1k", 1024, "1 KB", 6000], ["16k", 16384, "16 KB", 6000], ["128k", 131072, "128 KB", 10000], ["1024k", 1048576, "1 MB", 20000]];

async function runMtu() {
    const m = S.mtu;
    if (m.running) return;
    m.running = true;
    m.results = [];
    for (const [file, , label, ms] of MTU_SIZES) m.results.push({ dir: "down", file, label, ms: 0, deadline: ms });
    for (const [, bytes, label, ms] of MTU_SIZES) m.results.push({ dir: "up", bytes, label, ms: 0, deadline: ms });
    draw();
    // A lost large packet does not fail a request, it stalls it: the
    // deadline is what turns a blackhole into an answer.
    for (const r of m.results) {
        try {
            const res = r.dir === "down" ? await download("/mtu/" + r.file + ".bin", null, r.deadline) : await upload(r.bytes, r.deadline);
            r.ok = true;
            r.ms = res.ms;
        } catch {
            r.ok = false;
        }
        draw();
    }
    m.running = false;
    draw();
}

function nonce() {
    const b = new Uint8Array(8);
    crypto.getRandomValues(b);
    return "n" + Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

async function runLeak() {
    const l = S.leak;
    if (l.running) return;
    l.running = true;
    l.nonce = nonce();
    l.found = null;
    draw();
    // A name nobody asked for before, under a zone only the tunnel's resolver
    // answers. Another origin, so the answer is opaque; that it arrived at all
    // is the whole result.
    try {
        await get("http://" + l.nonce + ".leak.vpn/cgi-bin/whoami", 6000, { mode: "no-cors" });
        l.found = true;
    } catch {
        l.found = false;
    }
    l.running = false;
    draw();
}

async function lookup(name) {
    if (!name) return;
    S.answer = { asked: name, pending: true };
    draw();
    try {
        const a = kv(await (await get("/cgi-bin/lookup?name=" + encodeURIComponent(name), 8000)).text());
        S.answer = Object.assign({ asked: name }, a);
    } catch {
        S.answer = { asked: name, status: "fail" };
    }
    draw();
}

/* ── the frame ─────────────────────────────────────────────────────────── */

const host = location.hostname.toLowerCase();
const HOST_IS_NAME = /\.vpn$/.test(host);
// Opened by address rather than by name, the page is picked by the fragment
// instead (http://172.29.172.253/#dns), so every page still works for a
// client whose lookups do not reach the tunnel's resolver.
const byHash = location.hash.slice(1);
const current = host === "leak.vpn" || host.endsWith(".leak.vpn")
    ? "leak"
    : PAGES.find((p) => host === p + ".vpn")
        || (!HOST_IS_NAME && PAGES.includes(byHash) ? byHash : "amiunder");
const pageUrl = (p) => (HOST_IS_NAME ? "http://" + p + ".vpn/" : "#" + p);

function detectLang() {
    try {
        const saved = localStorage.getItem("amiunder-lang");
        if (saved === "ru" || saved === "en") return saved;
    } catch { /* storage may be off; the browser's language still decides */ }
    return (navigator.language || "ru").toLowerCase().startsWith("en") ? "en" : "ru";
}

function setLang(l) {
    lang = l;
    try { localStorage.setItem("amiunder-lang", l); } catch { /* per-visit only, then */ }
    draw();
}

let queued = false;
function drawSoon() {
    if (queued) return;
    queued = true;
    requestAnimationFrame(() => { queued = false; draw(); });
}

function draw() {
    const t = T();
    document.documentElement.lang = lang;
    const shown = HOST_IS_NAME ? host : current + ".vpn";
    document.title = shown + " · " + t[current].title;
    $("host").textContent = shown;
    $("lang-ru").classList.toggle("on", lang === "ru");
    $("lang-en").classList.toggle("on", lang === "en");

    const nav = $("nav");
    nav.replaceChildren();
    for (const p of PAGES) {
        const a = el("a", p === current ? "on" : "", t.nav[p]);
        a.href = pageUrl(p);
        nav.append(a);
    }

    // Keep the lookup box's text and focus across redraws.
    const typing = document.activeElement && document.activeElement.tagName === "INPUT"
        ? document.activeElement.value : null;
    const root = $("page");
    root.replaceChildren();
    page[current](root);
    if (typing !== null) {
        const input = root.querySelector("input");
        if (input) { input.value = typing; input.focus(); }
    }
    $("foot").textContent = t[current].foot;
}

window.addEventListener("hashchange", () => { if (!HOST_IS_NAME) location.reload(); });
$("lang-ru").addEventListener("click", () => setLang("ru"));
$("lang-en").addEventListener("click", () => setLang("en"));

lang = detectLang();
draw();
loadIp();
if (current === "node" || current === "mtu") loadNode();
if (current === "dns") loadDns();
if (current === "leak") runLeak();
