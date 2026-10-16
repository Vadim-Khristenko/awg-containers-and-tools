//! Bilingual strings.
//!
//! A table rather than a framework: the string set is small, it has to work in
//! a `scratch` container with no locale data, and translations that live next to
//! each other are the ones that stay in sync.
//!
//! Language comes from `--lang`, then `AWG_LANG`, then `LANG`/`LC_ALL`, then
//! English.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    En,
    Ru,
}

impl Lang {
    pub fn detect(explicit: Option<&str>) -> Self {
        let raw = explicit
            .map(str::to_string)
            .or_else(|| std::env::var("AWG_LANG").ok())
            .or_else(|| std::env::var("LC_ALL").ok())
            .or_else(|| std::env::var("LANG").ok())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if raw.starts_with("ru") {
            Lang::Ru
        } else {
            Lang::En
        }
    }
}

/// `t(lang, Key::Foo)` — every key carries both translations, so a missing one
/// is a compile error rather than a silent English fallback.
macro_rules! strings {
    ($($key:ident => ($en:expr, $ru:expr)),+ $(,)?) => {
        #[derive(Debug, Clone, Copy)]
        pub enum Key { $($key),+ }

        pub fn t(lang: Lang, key: Key) -> &'static str {
            match (lang, key) {
                $((Lang::En, Key::$key) => $en,)+
                $((Lang::Ru, Key::$key) => $ru,)+
            }
        }
    };
}

strings! {
    Tagline => (
        "AmneziaWG containers and tools — generate, validate and deploy AWG 1.0 through 3.1",
        "Контейнеры и инструменты AmneziaWG — генерация, проверка и развёртывание AWG 1.0–3.1"
    ),
    JointRelease => (
        "A joint release of Any Tech ARCHITECT and VAIEXIA",
        "Совместный релиз Any Tech ARCHITECT и VAIEXIA"
    ),
    AboutVaiexia => (
        "VAIEXIA — free, self-hostable server and VPN management, all in Rust + WASM.\nInstall any package to your server from anywhere and connect to it.\nBe simple, be powerful.",
        "VAIEXIA — свободное самохостируемое управление серверами и VPN, целиком на Rust + WASM.\nСтавьте любой пакет на свой сервер откуда угодно и подключайтесь к нему.\nПросто и мощно."
    ),
    Unofficial => (
        "Unofficial. Not affiliated with AmneziaVPN.",
        "Неофициальный проект. Не связан с AmneziaVPN."
    ),
    UsageHeader => ("Usage", "Использование"),
    CmdBare => (
        "open the interactive UI (this is what you get with no arguments)",
        "открыть интерактивный интерфейс (именно он запускается без аргументов)"
    ),
    CmdGen => ("generate a parameter set", "сгенерировать набор параметров"),
    CmdInstall => ("deploy a server over SSH (interactive)", "развернуть сервер по SSH (интерактивно)"),
    CmdDonate => ("support the project", "поддержать проект"),
    CmdAbout => ("about this tool", "о программе"),
    OptVersion => ("protocol version: 1.0 | 1.5 | 2.0 | 3.0 | 3.1", "версия протокола: 1.0 | 1.5 | 2.0 | 3.0 | 3.1"),
    OptUapi => ("emit UAPI lines instead of .conf", "вывести строки UAPI вместо .conf"),
    OptMihomo => (
        "emit a mihomo (Clash.Meta) proxy entry instead of .conf",
        "вывести блок прокси для mihomo (Clash.Meta) вместо .conf"
    ),
    OptJson => ("emit the config as JSON, for scripts", "выдать конфиг в JSON — для скриптов"),
    OptOut => ("write the result to a file instead of stdout", "записать результат в файл вместо stdout"),
    OptSwitchesNote => (
        "switches start from the version's preset; each takes on|off (alone means on)",
        "переключатели стартуют с пресета версии; каждый принимает on|off (без значения значит on)"
    ),
    OptHeaderProtection => (
        "3.x: HeaderProtectionKey, written into both ends (on for 3.0 and 3.1)",
        "3.x: HeaderProtectionKey, пишется в оба конца (на 3.0 и 3.1 включён)"
    ),
    OptContentPadding => (
        "3.x: ContentPaddingAddition, extra random transport padding",
        "3.x: ContentPaddingAddition, дополнительный случайный паддинг транспорта"
    ),
    OptRandomTimings => (
        "3.x: randomised protocol timers instead of WireGuard's constants",
        "3.x: случайные таймеры протокола вместо констант WireGuard"
    ),
    OptSameS => (
        "3.1 with protection and trailers: one value for S1-S4 (not recommended: a shared value is a fingerprint)",
        "3.1 с защитой и хвостами: одно значение для S1-S4 (не рекомендуется: общее значение это отпечаток)"
    ),
    OptDisableH => (
        "3.1 with protection and trailers: H1-H4 as 1, 2, 3, 4 (on by default on 3.1)",
        "3.1 с защитой и хвостами: H1-H4 как 1, 2, 3, 4 (на 3.1 включено по умолчанию)"
    ),
    OptTags => (
        "turn a chain tag kind off (or back on); the engines still decide what is allowed",
        "выключить (или включить) вид тега в цепочках; что допустимо, всё равно решают движки"
    ),
    OptAttempt => (
        "failed attempts so far; past 3 everything is generated one notch stronger",
        "сколько попыток уже не прошло; после 3 всё генерируется на ступень сильнее"
    ),
    ErrBadAttempt => ("--attempt out of range", "--attempt вне допустимого диапазона"),
    OptRandomTrailers => (
        "3.1: a random-length trailer on every outgoing packet (on by default on 3.1, with MTU 1280)",
        "3.1: случайный по длине хвост у каждого исходящего пакета (на 3.1 включён, MTU 1280)"
    ),
    OptDisableCookies => (
        "3.1: never send cookie replies (breaks NAT keepalive under load)",
        "3.1: не отправлять cookie-ответы (ломает keepalive за NAT под нагрузкой)"
    ),
    OptIntensity => ("obfuscation intensity: low | medium | high", "интенсивность обфускации: low | medium | high"),
    OptRouter => ("low-power router mode (minimal noise)", "режим слабого роутера (минимум шума)"),
    OptLang => ("interface language: en | ru", "язык интерфейса: en | ru"),
    WhyUnique => (
        "Every install generates its own parameters. A shared set would give every\nserver built with this tool one DPI fingerprint.",
        "Каждая установка генерирует свои параметры. Общий набор дал бы всем\nсерверам, собранным этим инструментом, один отпечаток для DPI."
    ),
    DonateIntro => (
        "This tool is free and always will be. If it saved you time:",
        "Инструмент бесплатный и таким останется. Если он сэкономил вам время:"
    ),
    DonateArchitect => ("Config generator", "Генератор конфигураций"),
    DonateSources => ("Sources and issues", "Исходники и баг-репорты"),
    AboutAwg3 => (
        "AWG 3.x support exists because these images configure the device over\nUAPI: one request format covers 1.0 through 3.1, and the keys reach the\ndaemon as it parses them. 3.1 adds two switches — RandomTrailers appends a\nrandom tail to every outgoing packet, DisableCookies silences cookie replies —\nboth off by default, because a server that quietly breaks NAT keepalive is\nworse than one turned on knowingly.",
        "Поддержка AWG 3.x есть, потому что эти образы настраивают устройство через\nUAPI: один формат запроса покрывает 1.0–3.1, и ключи доходят до демона в том\nвиде, в каком он их парсит. В 3.1 два переключателя: RandomTrailers дописывает\nслучайный хвост каждому исходящему пакету, DisableCookies запрещает\ncookie-ответы — оба выключены по умолчанию: сервер, который тихо ломает NAT\nkeepalive, хуже включённого осознанно."
    ),
    MenuGenerate => ("Generate a configuration", "Сгенерировать конфигурацию"),
    MenuDeploy => ("Deploy to a server", "Развернуть на сервере"),
    MenuAbout => ("About", "О программе"),
    MenuDonate => ("Support the project", "Поддержать проект"),
    LblIntensity => ("intensity", "интенсивность"),
    LblJunk => ("junk level", "уровень мусора"),
    LblRouter => ("router mode", "режим роутера"),
    LblExtreme => ("extreme", "экстремальный режим"),
    LblRelease => ("client build", "сборка клиента"),
    LblSet => ("saved set", "набор"),
    HintNaming => ("name for the set (Enter saves, Esc cancels):", "имя набора (Enter сохраняет, Esc отмена):"),
    LblServerEngine => ("server engine", "движок сервера"),
    LblRegion => ("host region", "регион хостов"),
    LblWhitelisted => ("whitelist", "белый список"),
    LblBrowser => ("browser", "браузер"),
    LblAttempt => ("attempt", "попытка"),
    LblMimicAll => ("mimic I2-I5", "мимикрия I2-I5"),
    LblRandomTimings => ("random timers", "случайные таймеры"),
    LblSameS => ("unite S1-S4", "единые S1-S4"),
    LblDisableH => ("H1-H4 = 1-4", "H1-H4 = 1-4"),
    ValAny => ("any", "любой"),
    ValCurrent => ("current", "текущая"),
    LblNarrowH => ("narrow H (3.1)", "узкие H (3.1)"),
    LblFormat => ("format", "формат"),
    HintRegenerate => ("regenerate", "перегенерировать"),
    HintSaveSet => ("save as a set", "сохранить набор"),
    HintBack => ("back", "назад"),
    StatusGenerated => ("Fresh parameters generated", "Сгенерирован новый набор параметров"),
    CmdClients => ("supported clients and their limits", "поддерживаемые клиенты и их ограничения"),
    CmdProfiles => ("available mimicry profiles", "доступные профили мимикрии"),
    CmdSets => (
        "saved generator settings: gen --save NAME writes one, --set NAME uses it",
        "сохранённые настройки генератора: gen --save ИМЯ сохраняет, --set ИМЯ применяет"
    ),
    CmdCheck => (
        "check a .conf or vpn:// link someone else wrote; exit 0 clean, 1 warnings, 2 errors",
        "проверить чужой .conf или ссылку vpn://; код 0 чисто, 1 предупреждения, 2 ошибки"
    ),
    CmdPeer => (
        "issue, list and revoke peers on a node, here or over SSH",
        "выдать, показать и отозвать пиров на узле, здесь или по SSH"
    ),
    CmdDns => (
        "the tunnel's resolver: state, block and allow lists, lookups",
        "резолвер туннеля: состояние, списки блокировки и разрешения, запросы"
    ),
    CmdUnder => (
        "am I under the VPN? Asks the tunnel resolver and the amiunder.vpn page from this machine",
        "я под VPN? Спрашивает резолвер туннеля и страницу amiunder.vpn с этой машины"
    ),
    UnderYes => (
        "under the VPN: the page answered through the tunnel and sees this machine as",
        "под VPN: страница ответила через туннель и видит эту машину как"
    ),
    UnderNo => (
        "not under the VPN: the page did not answer, so traffic does not go through the tunnel",
        "не под VPN: страница не ответила, трафик не идёт через туннель"
    ),
    UnderDnsNone => (
        "no answer from the tunnel resolver",
        "нет ответа от резолвера туннеля"
    ),
    UnderSystemYes => (
        "this machine's own resolver knows .vpn: its DNS goes through the tunnel",
        "свой резолвер этой машины знает .vpn: её DNS идёт через туннель"
    ),
    UnderSystemNo => (
        "this machine's own resolver does not know .vpn: its DNS goes elsewhere, a leak if the tunnel is up",
        "свой резолвер этой машины не знает .vpn: её DNS идёт мимо, при поднятом туннеле это утечка"
    ),
    ErrBadResolver => ("--resolver wants an IPv4 address", "--resolver ждёт адрес IPv4"),
    ErrBadTimeout => ("--timeout wants seconds, 1 to 60", "--timeout ждёт секунды, от 1 до 60"),    CmdHosts => (
        "hosts the mimicry profiles may name, by role and region",
        "хосты, которые могут называть профили мимикрии, по ролям и регионам"
    ),
    OptRegion => (
        "where the named hosts should be plausible: ru | global | eu | uk | by | cn | any (default any)",
        "где названные хосты правдоподобны: ru | global | eu | uk | by | cn | any (по умолчанию any)"
    ),
    OptWhitelisted => (
        "only name hosts on this region's whitelist (what still works when the network is cut down)",
        "называть только хосты из белого списка региона (то, что работает при ограничениях сети)"
    ),
    OptRole => (
        "for `hosts`: quic | tls | dtls | sip | stun | dns",
        "для `hosts`: quic | tls | dtls | sip | stun | dns"
    ),
    OptUnknown => (
        "for `hosts`: include hosts whose facts were never established",
        "для `hosts`: включить хосты, про которые ничего не установлено"
    ),
    ErrCheckWhat => (
        "check what? Give a .conf path, - for stdin, or a vpn:// link",
        "что проверить? Укажи путь к .conf, - для stdin или ссылку vpn://"
    ),
    MsgInferred => ("read off its fields", "определена по полям"),
    MsgNotAwg => (
        "no AmneziaWG parameters in it",
        "в нём нет параметров AmneziaWG"
    ),
    MsgCheckClean => ("nothing to report", "замечаний нет"),
    MsgWrote => ("written to", "записано в"),
    MsgNoResolver => (
        "no resolver container here (vaiprog/amnezia-wg-dns); --container names one",
        "здесь нет контейнера резолвера (vaiprog/amnezia-wg-dns); --container укажет его"
    ),
    MsgDnsReloads => (
        "the resolver picks it up within a few seconds, no restart",
        "резолвер подхватит это за несколько секунд, без перезапуска"
    ),
    MsgNoAnswer => ("no answer", "ответа нет"),
    LblMode => ("mode", "режим"),
    LblBlocked => ("blocked", "заблокировано"),
    LblAllowed => ("allowed", "разрешено"),
    LblQueries => ("queries", "запросов"),
    LblCacheHits => ("from cache", "из кэша"),
    MsgSaved => ("saved the set", "набор сохранён:"),
    MsgRemoved => ("removed the set", "набор удалён:"),
    MsgNoSets => (
        "no saved sets yet: gen ... --save NAME writes one",
        "сохранённых наборов пока нет: gen ... --save ИМЯ сохраняет набор"
    ),
    ErrUnknownSet => ("no saved set by that name", "нет сохранённого набора с таким именем"),
    MsgNoPeers => ("no peers on this node yet", "на этом узле пока нет пиров"),
    ErrUnknownRegion => ("unknown region", "неизвестный регион"),
    ErrUnknownRole => ("unknown role", "неизвестная роль"),
    OptProfile => (
        "protocol the I1 packet imitates (see `awg-tool profiles`)",
        "протокол, под который маскируется пакет I1 (см. `awg-tool profiles`)"
    ),
    OptClient => (
        "target client; parameters are trimmed to what it accepts",
        "целевой клиент: параметры подрезаются под его ограничения"
    ),
    OptMtu => ("path MTU the junk packets must fit into", "MTU пути, в который должны влезть мусорные пакеты"),
    OptHost => (
        "host name to imitate instead of one from the host database (`--mimic-host` in install, where --host is the server)",
        "имя хоста для мимикрии вместо выбранного из базы хостов (`--mimic-host` в install, где --host это сервер)"
    ),
    OptBrowser => (
        "match a browser's measured packet sizes: chrome | edge | firefox | safari | ios | yandex-desktop | yandex-mobile | 360 | qq",
        "подогнать размеры пакетов под браузер: chrome | edge | firefox | safari | ios | yandex-desktop | yandex-mobile | 360 | qq"
    ),
    OptMimicAll => (
        "build all five packets from the profile, not just I1",
        "строить по профилю все пять пакетов, а не только I1"
    ),
    OptTagC => (
        "accepted for old scripts; <c> is now used wherever both engines parse it",
        "оставлен для старых скриптов: <c> теперь ставится везде, где его парсят оба движка"
    ),
    OptClientRelease => (
        "an older build of the client whose limits differ (see `awg-tool clients`)",
        "старая сборка клиента с другими ограничениями (см. `awg-tool clients`)"
    ),
    OptServerEngine => (
        "what parses I1-I5 on the server: go (default, these images) | kmod | awg-quick | kmod-bsd | unverified",
        "что разбирает I1-I5 на сервере: go (по умолчанию, эти образы) | kmod | awg-quick | kmod-bsd | unverified"
    ),
    OptJunk => (
        "junk packets before the handshake, 0..32 (default 5)",
        "мусорных пакетов перед хендшейком, 0..32 (по умолчанию 5)"
    ),
    OptExtreme => (
        "push ceilings: Jc to 128, S3 past 64, wide H windows",
        "поднять потолки: Jc до 128, S3 за 64, широкие окна H"
    ),
    OptNarrowH => (
        "3.1 header windows: narrow (~20k, a CPU workaround) or wide; narrow by default on 3.1, and always with --random-trailers",
        "окна заголовков 3.1: narrow (~20k, обход нагрузки CPU) или wide; на 3.1 по умолчанию narrow, а с --random-trailers всегда"
    ),
    ErrBadJunk => ("--junk out of range", "--junk вне допустимого диапазона"),
    Available => ("available", "доступно"),
    DefaultClient => ("default client", "клиент по умолчанию"),
    WarningsHeader => ("configuration warnings", "предупреждения по конфигурации"),
    KnownIssue => ("known issue", "известная проблема"),
    ErrUnknownCmd => ("unknown command", "неизвестная команда"),
    ErrUnknownVersion => ("unsupported protocol version", "неподдерживаемая версия протокола"),
    ErrUnknownProfile => ("unknown mimicry profile", "неизвестный профиль мимикрии"),
    ErrUnknownClient => ("unknown client", "неизвестный клиент"),
    ErrUnknownEngine => ("unknown engine", "неизвестный движок"),
    ErrUnknownRelease => ("unknown release of this client", "у этого клиента нет такой сборки"),
    ErrUnknownBrowser => ("unknown browser profile", "неизвестный профиль браузера"),
    ErrBadMtu => ("MTU out of range", "MTU вне допустимого диапазона"),
    // ── talking to a server ─────────────────────────────────────────────
    CmdStatus => (
        "what is running on a server, and how it is doing",
        "что запущено на сервере и как оно себя чувствует"
    ),
    CmdLogs => (
        "a node's log, with keys stripped out",
        "журнал узла, с вырезанными ключами"
    ),
    CmdDoctor => (
        "work out why a node is not carrying traffic",
        "разобраться, почему узел не везёт трафик"
    ),
    CmdUpdate => (
        "is this tool, or an image on a server, out of date?",
        "не устарел ли сам инструмент или образ на сервере"
    ),
    UsageServerFlags => (
        "For the commands that talk to a server",
        "Для команд, которые ходят на сервер"
    ),
    OptSshPort => ("SSH port (default 22)", "порт SSH (по умолчанию 22)"),
    OptProfileFlag => ("a saved connection, by name", "сохранённое подключение по имени"),
    OptHostFlag => ("connect to this address instead of a saved profile", "подключиться по адресу вместо сохранённого профиля"),
    OptUserFlag => ("log in as this user (default: root)", "входить этим пользователем (по умолчанию root)"),
    OptKeyFlag => ("private key file to authenticate with", "файл приватного ключа для входа"),
    OptSudoFlag => ("docker on that host needs sudo", "docker на том хосте требует sudo"),
    OptLocal => (
        "use the docker on this machine instead of a saved profile",
        "использовать docker на этой машине вместо сохранённого профиля"
    ),
    OptContainer => (
        "container to act on: its name, or auto for the single running node",
        "контейнер для действия: имя или auto для единственного запущенного узла"
    ),
    MsgLocally => ("this machine", "этой машине"),
    OptLinesFlag => ("how many log lines to fetch", "сколько строк журнала забрать"),
    MsgConnecting => ("connecting to", "подключаюсь к"),
    MsgUnknownHost => (
        "This is the first time this tool has seen",
        "Этот инструмент впервые видит"
    ),
    MsgVerifyFingerprint => (
        "Check that against the server's own `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`.",
        "Сверьте это с выводом `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` на самом сервере."
    ),
    AskTrustHost => ("Trust this host?", "Доверять этому хосту?"),
    MsgNotTrusted => ("not trusted, nothing was sent", "не доверяем, ничего не отправлено"),
    MsgMismatchAdvice => (
        "This is not a first connection — the key changed. Either the server was rebuilt, or something is between you and it. Confirm out of band and edit known_hosts by hand.",
        "Это не первое подключение — ключ сменился. Либо сервер пересобрали, либо между вами кто-то стоит. Проверьте по другому каналу и правьте known_hosts руками."
    ),
    MsgSurveying => ("Looking the machine over…", "Осматриваю машину…"),
    MsgDeploying => ("Setting the server up…", "Поднимаю сервер…"),
    MsgWillInstall => ("These packages are missing", "Не хватает этих пакетов"),
    AskRunIt => ("Run that?", "Выполнить?"),
    MsgAborted => ("nothing was changed", "ничего не изменено"),
    MsgInstallFailed => ("the install command failed", "команда установки не отработала"),
    MsgRechecking => ("Looking again, now that it is installed…", "Смотрю ещё раз, теперь уже с установленным…"),
    MsgDockerStillUnusable => (
        "docker is still not usable after the install; check `systemctl status docker` on that host",
        "docker после установки всё ещё недоступен; посмотрите `systemctl status docker` на том хосте"
    ),
    DonateCrypto => ("Crypto", "Криптовалюты"),
    DonateFiat => ("Cards and recurring", "Карты и регулярная поддержка"),
    DonateNetworkWarn => (
        "Send on the network named beside each address. The wrong network is unrecoverable.",
        "Отправляйте по той сети, что указана рядом с адресом. Не та сеть — деньги не вернуть."
    ),
    MsgPortBusy => ("something is already listening on", "на этом порту уже кто-то слушает"),
    MsgPickAnotherPort => (
        "pass --listen-port with a free one; nothing here will kill another process for you",
        "укажите свободный через --listen-port; убивать чужой процесс за вас тут никто не станет"
    ),
    LblSystem => ("system", "система"),
    LblDocker => ("docker", "docker"),
    LblAddress => ("address", "адрес"),
    LblEndpoint => ("endpoint", "точка входа"),
    LblContainer => ("container", "контейнер"),
    OptListenPort => ("UDP port for the tunnel (default 51820)", "UDP-порт туннеля (по умолчанию 51820)"),
    OptEndpoint => ("address clients should connect to", "адрес, на который будут подключаться клиенты"),
    OptPull => ("allow pulling the image if it is not on the target", "разрешить скачать образ, если его нет на сервере"),
    MsgNoContainers => (
        "No AmneziaWG containers found on that host.",
        "На этом хосте контейнеров AmneziaWG не найдено."
    ),
    MsgNoFaults => ("nothing wrong that I can see", "ничего плохого не вижу"),
    PromptSecret => ("password or passphrase for", "пароль или пассфраза для"),
    PromptSudo => ("sudo password for", "пароль sudo для"),
    LblPeers => ("peers", "пиры"),
    LblHandshake => ("handshake", "хендшейк"),
    ValNever => ("never", "никогда"),
    ErrProfileAndHost => (
        "--profile and --host are alternatives; pass one or the other",
        "--profile и --host — это альтернативы, укажите что-то одно"
    ),
    ErrNoSuchProfile => ("no saved profile by that name", "сохранённого профиля с таким именем нет"),
    ErrNoProfiles => (
        "no saved profiles yet — pass --host, or save one first",
        "сохранённых профилей пока нет — укажите --host или сначала сохраните профиль"
    ),
    ErrPickProfile => (
        "several profiles are saved; name one with --profile",
        "сохранено несколько профилей, назовите нужный через --profile"
    ),
    ErrNoSuchContainer => ("no such container on that host", "на этом хосте нет такого контейнера"),

    // ── navigation ──────────────────────────────────────────────────────
    NavHome => ("Home", "Главная"),
    HintMove => ("move", "перейти"),
    HintOpen => ("open", "открыть"),
    HintChange => ("change", "изменить"),
    HintQuit => ("quit", "выход"),
    HintScroll => ("scroll", "прокрутка"),
    HintQuitFromHere => (
        "This is the top level — press q to quit.",
        "Это верхний уровень — нажмите q, чтобы выйти."
    ),

    // ── menu ────────────────────────────────────────────────────────────
    MenuGenerateSub => (
        "Parameters for any of the four protocol versions",
        "Параметры для любой из четырёх версий протокола"
    ),
    MenuDeploySub => (
        "Put a server on a machine you own, over SSH",
        "Поставить сервер на свою машину по SSH"
    ),
    MenuServers => ("Servers", "Серверы"),
    MenuServersSub => (
        "What is running out there, and why it is unhappy",
        "Что там крутится и почему оно недовольно"
    ),
    LblThisMachine => ("this machine (docker)", "эта машина (docker)"),
    MenuPeers => ("peers", "пиры"),
    HintBlock => ("block/unblock", "блок/снять"),
    HintAllow => ("allow/unallow", "разрешить/снять"),
    HintQuery => ("look up", "запрос"),
    HintPeerAddRm => ("issue/revoke", "выдать/отозвать"),
    HintConfirm => ("do it", "выполнить"),
    HintCancel => ("cancel", "отмена"),
    AskBlock => ("Block a name (and everything under it)", "Заблокировать имя (и всё под ним)"),
    AskUnblock => ("Take a name off the blocklist", "Убрать имя из блок-листа"),
    AskAllow => ("Allow a name whatever the lists say", "Разрешить имя, что бы ни говорили списки"),
    AskUnallow => ("Take a name off the allowlist", "Убрать имя из списка разрешённых"),
    AskQuery => ("Ask the resolver for a name", "Спросить у резолвера имя"),
    AskPeerAdd => ("Label for the new peer", "Метка нового пира"),
    AskPeerRm => ("Label or public key of the peer to revoke", "Метка или публичный ключ пира для отзыва"),
    MsgPeerPrivate => (
        "The config holds the peer's private key: hand it over privately.",
        "В конфиге приватный ключ пира: передавайте его лично."
    ),    MenuDoctor => ("diagnose", "диагностика"),
    MenuLogs => ("logs", "журнал"),
    PanelProfiles => ("Saved connections", "Сохранённые подключения"),
    PanelNodes => ("Nodes", "Узлы"),
    PanelDetail => ("Details", "Подробности"),
    HintSwitchPane => ("switch pane", "сменить панель"),
    HintConnect => ("connect", "подключиться"),
    HintRefresh => ("refresh", "обновить"),
    HintPickProfile => (
        "Pick a connection and press Enter.",
        "Выберите подключение и нажмите Enter."
    ),
    MsgNoSavedProfiles => (
        "No saved connections yet. `awg-tool status --host ADDR` can reach a server without one.",
        "Сохранённых подключений пока нет. До сервера можно достать и без них: `awg-tool status --host АДРЕС`."
    ),
    MsgNeedsCli => (
        "This connection needs a password, which this screen will not ask for. Use",
        "Этому подключению нужен пароль, а этот экран его не спрашивает. Используйте"
    ),
    LblUnreachable => ("no answer", "не отвечает"),
    MenuAboutSub => ("What this is, and why it exists", "Что это такое и зачем"),
    MenuCheck => ("Check a config", "Проверить конфиг"),
    MenuCheckSub => (
        "a .conf or vpn:// link someone else wrote, against the chosen client",
        "чужой .conf или ссылку vpn:// под выбранный клиент"
    ),
    CheckPrompt => (
        "path to a .conf, or a vpn:// link; Enter checks, Esc leaves",
        "путь к .conf или ссылка vpn://; Enter проверяет, Esc назад"
    ),
    CheckHint => (
        "Client and server engine are the ones chosen on the generate screen.",
        "Клиент и движок сервера берутся с экрана генерации."
    ),
    StatusFindings => ("findings", "замечаний"),
    MenuDonateSub => (
        "It is free, and stays free",
        "Он бесплатный и таким останется"
    ),

    // ── generate screen ─────────────────────────────────────────────────
    PanelOptions => ("Options", "Параметры"),
    PanelClient => ("Client limits", "Ограничения клиента"),
    PanelWarnings => ("Checks", "Проверки"),
    LblVersion => ("version", "версия"),
    LblProfile => ("mimicry", "мимикрия"),
    LblClient => ("client", "клиент"),
    ValLow => ("low", "низкая"),
    ValMedium => ("medium", "средняя"),
    ValHigh => ("high", "высокая"),
    ValOn => ("on", "вкл"),
    ValOff => ("off", "выкл"),

    // ── deploy screen ───────────────────────────────────────────────────
    DeployHow => (
        "Run `awg-tool install`. It asks where to go and how to get in, then looks\nthe machine over before it changes anything.",
        "Запустите `awg-tool install`. Он спросит, куда идти и как войти, а потом\nосмотрит машину, прежде чем что-то менять."
    ),
    DeploySteps => (
        "  1  Address, port, user.\n  \
           2  Password, key file, key with a passphrase, or your agent.\n  \
           3  It reads /etc/os-release and checks for docker, iptables, iproute2, curl.\n  \
           4  Anything missing is shown as the exact command first, and run only then.\n  \
           5  Parameters are generated for this server alone, and the container starts.\n\n\
        Connection profiles are remembered, so the second run is one keystroke.\n\
        A password reaches the disk only if you ask for it.",
        "  1  Адрес, порт, пользователь.\n  \
           2  Пароль, файл ключа, ключ с пассфразой или ваш агент.\n  \
           3  Он читает /etc/os-release и проверяет docker, iptables, iproute2, curl.\n  \
           4  Чего не хватает — сначала покажет точной командой и только потом выполнит.\n  \
           5  Параметры генерируются только для этого сервера, контейнер поднимается.\n\n\
        Профили подключения запоминаются, так что второй запуск — одно нажатие.\n\
        Пароль попадает на диск, только если вы сами об этом попросите."
    ),

    // ── about ───────────────────────────────────────────────────────────
    AboutOrigin => (
        "This started as a small thing to make installing AmneziaWG less tedious.\nThen it turned out nobody could self-host 3.0 at all — and, well, you only\nlive once. So it grew up into the operator of its own stack.\n\nOfficial self-hosted 3.0 will land upstream sooner or later. When it does,\nuse it. Until then, this works.",
        "Начиналось всё как утилита, чтобы ставить AmneziaWG было не так муторно.\nПотом выяснилось, что self-hosted 3.0 нет вообще ни у кого — ну а живём\nодин раз. Так оно и выросло в оператора собственного хозяйства.\n\nРано или поздно официальный self-hosted 3.0 появится в апстриме. Появится —\nпользуйтесь им. А пока работает это."
    ),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn russian_locales_are_detected_from_the_usual_variables() {
        assert_eq!(Lang::detect(Some("ru")), Lang::Ru);
        assert_eq!(Lang::detect(Some("ru_RU.UTF-8")), Lang::Ru);
        assert_eq!(Lang::detect(Some("en_GB")), Lang::En);
        // unknown locales fall back to English rather than panicking
        assert_eq!(Lang::detect(Some("fr_FR")), Lang::En);
    }

    #[test]
    fn both_languages_are_present_for_every_key() {
        for key in [
            Key::Tagline,
            Key::CmdGen,
            Key::DonateIntro,
            Key::AboutAwg3,
            Key::CmdClients,
            Key::CmdProfiles,
            Key::OptProfile,
            Key::OptClient,
            Key::OptBrowser,
            Key::WarningsHeader,
            Key::ErrUnknownProfile,
            Key::ErrUnknownClient,
            Key::ErrBadMtu,
        ] {
            assert!(!t(Lang::En, key).is_empty());
            assert!(!t(Lang::Ru, key).is_empty());
            assert_ne!(t(Lang::En, key), t(Lang::Ru, key));
        }
    }
}
