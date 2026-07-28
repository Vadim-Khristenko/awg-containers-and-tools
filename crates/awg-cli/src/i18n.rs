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
        "AmneziaWG containers and tools — generate, validate and deploy AWG 1.0 / 1.5 / 2.0 / 3.0",
        "Контейнеры и инструменты AmneziaWG — генерация, проверка и развёртывание AWG 1.0 / 1.5 / 2.0 / 3.0"
    ),
    JointRelease => (
        "A joint release of AmneziaWG Architect and VAIEXIA",
        "Совместный релиз AmneziaWG Architect и VAIEXIA"
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
    CmdGen => ("generate a parameter set", "сгенерировать набор параметров"),
    CmdInstall => ("deploy a server over SSH (interactive)", "развернуть сервер по SSH (интерактивно)"),
    CmdDonate => ("support the project", "поддержать проект"),
    CmdAbout => ("about this tool", "о программе"),
    OptVersion => ("protocol version: 1.0 | 1.5 | 2.0 | 3.0", "версия протокола: 1.0 | 1.5 | 2.0 | 3.0"),
    OptUapi => ("emit UAPI lines instead of .conf", "вывести строки UAPI вместо .conf"),
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
        "AWG 3.0 support exists here because upstream ships no self-hosted 3.0:\nthe server pipeline drives awg-quick, and amneziawg-tools still parses only\nthe 2.0 keys. The daemon does understand 3.0, so this tool configures it\nover UAPI directly.",
        "Поддержка AWG 3.0 здесь появилась потому, что у апстрима нет self-hosted 3.0:\nсерверный конвейер работает через awg-quick, а amneziawg-tools до сих пор\nразбирает только ключи 2.0. Сам демон 3.0 понимает — поэтому мы настраиваем\nего напрямую через UAPI."
    ),
    MenuGenerate => ("Generate a configuration", "Сгенерировать конфигурацию"),
    MenuDeploy => ("Deploy to a server", "Развернуть на сервере"),
    MenuAbout => ("About", "О программе"),
    MenuDonate => ("Support the project", "Поддержать проект"),
    LblIntensity => ("intensity", "интенсивность"),
    LblRouter => ("router mode", "режим роутера"),
    LblFormat => ("format", "формат"),
    HintRegenerate => ("regenerate", "перегенерировать"),
    HintBack => ("back", "назад"),
    StatusGenerated => ("Fresh parameters generated", "Сгенерирован новый набор параметров"),
    DeployPlanned => (
        "Planned: host, port, user, then password / key / key with passphrase / agent.",
        "В планах: адрес, порт, пользователь, затем пароль / ключ / ключ с пассфразой / агент."
    ),
    CmdClients => ("supported clients and their limits", "поддерживаемые клиенты и их ограничения"),
    CmdProfiles => ("available mimicry profiles", "доступные профили мимикрии"),
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
        "host name to imitate instead of one from the built-in pools",
        "имя хоста для мимикрии вместо выбранного из встроенных списков"
    ),
    OptBrowser => (
        "match a browser's measured packet sizes: chrome | edge | firefox | safari | yandex-desktop | yandex-mobile",
        "подогнать размеры пакетов под браузер: chrome | edge | firefox | safari | yandex-desktop | yandex-mobile"
    ),
    OptMimicAll => (
        "build all five packets from the profile, not just I1",
        "строить по профилю все пять пакетов, а не только I1"
    ),
    OptTagC => (
        "enable the <c> tag (off by default: ErrorCode 1000 on several builds)",
        "включить тег <c> (по умолчанию выключен: на ряде сборок ErrorCode 1000)"
    ),
    Available => ("available", "доступно"),
    DefaultClient => ("default client", "клиент по умолчанию"),
    WarningsHeader => ("configuration warnings", "предупреждения по конфигурации"),
    KnownIssue => ("known issue", "известная проблема"),
    ErrUnknownCmd => ("unknown command", "неизвестная команда"),
    ErrUnknownVersion => ("unsupported protocol version", "неподдерживаемая версия протокола"),
    ErrUnknownProfile => ("unknown mimicry profile", "неизвестный профиль мимикрии"),
    ErrUnknownClient => ("unknown client", "неизвестный клиент"),
    ErrUnknownBrowser => ("unknown browser profile", "неизвестный профиль браузера"),
    ErrBadMtu => ("MTU out of range", "MTU вне допустимого диапазона"),
    NotYetImplemented => (
        "not wired up yet in this build",
        "в этой сборке ещё не подключено"
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
