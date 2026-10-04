// Package i18n — локализация RU/EN. Русские строки — ключи: при lang=ru
// Tr() возвращает ключ как есть (исходники не меняются), при lang=en —
// перевод из словаря. Словарь — фриз-лист: только строки из исходников,
// ничего лишнего. Ключи и переводы держим в актуальном виде вместе.
package i18n

var lang = "ru"

// SetLang выставляет язык ("ru" / "en"); прочие значения = ru.
func SetLang(l string) {
	if l == "en" {
		lang = "en"
		return
	}
	lang = "ru"
}

// Lang — текущий язык.
func Lang() string { return lang }

// en — англ. словарь = translate.md. Ключи — точные русские строки.
var en = map[string]string{
	// ── меню + выход ──
	"меню":                                "menu",
	"ломать камеры":                       "hack cameras",
	"расшифровать .xml от smartpss":       "decrypt smartpss .xml",
	"искать префиксы с списка IP":         "find prefixes from IP list",
	"настройки":                           "settings",
	"пре-флайт (%s)":                      "preflight (%s)",
	"пре-флайт?":                          "preflight?",
	"пре-флайт…":                          "preflight…",
	"пре-флайт: все векторы глухи (33044/33045/39943/6117)": "preflight: all vectors dead (33044/33045/39943/6117)",
	"%s — SKIP: %s":            "%s — SKIP: %s",
	"%s — пре-флайт: %s":       "%s — preflight: %s",
	"ошибка: %v":                       "error: %v",
	"↑↓ навигация  ·  enter / 0-9 - выбор  ·  q - выход":                        "↑↓ navigate  ·  enter / 0-9 - select  ·  q - quit",
	"↑↓ навигация  ·  enter / 0-9 - выбор  ·  esc - назад  ·  q - выход":        "↑↓ navigate  ·  enter / 0-9 - select  ·  esc - back  ·  q - quit",
	"↑↓ навигация  ·  enter/пробел - переключить  ·  esc — назад  ·  q - выход": "↑↓ navigate  ·  enter/space - toggle  ·  esc — back  ·  q - quit",

	// ── smartpss-подменю ──
	"расшифровать XML файл":                     "decrypt XML file",
	"расшифровать blob (base64 → пароль)":       "decrypt blob (base64 → password)",
	"собрать xml с results.csv":                 "build xml from results.csv",
	"креды → xml":                               "creds → xml",
	"файл с кредами (SN,login:pass)":            "creds file (SN,login:pass)",
	"выходной xml-файл":                         "output xml file",
	"[!] нет разобранных кредов":                "[!] no parsed creds",
	"[+] %d камер -> %s":                        "[+] %d cams -> %s",
	" (мимо формата: %d)":                       " (skipped malformed: %d)",
	" (%d файла(ов) по 64)":                     " (%d file(s) of 64)",
	"назад":                                     "back",

	// ── настройки + редактор титров ──
	"снапы (%s)":                "snapshots (%s)",
	"настройки OSDChanger (%s)": "OSDChanger settings (%s)",
	"   └ channel title: %s":    "   └ channel title: %s",
	"   └ OSD слот %d: %s":      "   └ OSD slot %d: %s",
	"(пусто)":                   "(empty)",
	"титры":                     "titles",
	"впиши сюда что-то, что будут видеть все:":          "write something everyone will see:",
	"! до %d символов ! пусто — поле не используется !": "! up to %d chars ! if empty - field will be unused !",
	"ограничение: максимум %d символов (у тебя %d)":     "limit: max %d chars (you have %d)",
	"channel title":       "channel title",
	"текст OSD-слота %d ": "OSD slot %d text ",
	"enter - сохранить  ·  esc - назад  ·  ctrl+c - выход": "enter - save  ·  esc - back  ·  ctrl+c - quit",

	// ── редактор кредов юзера ──
	"добавить нового юзера":              "add user",
	"креды юзера":                        "user creds",
	"новый юзер в формате login:passwd:": "new user as login:passwd:",
	"нужен формат login:passwd":          "need login:passwd format",
	"лог-режим (%s)":                     "log mode (%s)",

	// ── формы ──
	"обязательное поле":                                       "required field",
	"такого файла нет! перепиши, пожалуйста":                  "no such file! fix it, please",
	"y/n - да/нет · enter - далее · q - выход · esc - в меню": "y/n - yes/no · enter - next · q - quit · esc - menu",
	"enter - далее · esc - в меню · ctrl+c - выход":           "enter - next · esc - menu · ctrl+c - quit",
	"[да]":  "[yes]",
	"[нет]": "[no]",
	"вкл":   "on",
	"выкл":  "off",
	"нужна кое какая информация": "need some info",
	"папка для результатов":      "results folder",
	"потоков":                    "threads",
	"снапы?":                     "snapshots?",
	"список префиксов пуст":                                            "prefix list is empty",
	"xml → креды":                           "xml → creds",
	"файл с результатами (SmartPSS export)": "results file (SmartPSS export)",
	"название файла для кредов":             "creds output filename",
	"[!] нет декодированных кредов":         "[!] no decoded creds",
	"[+] %d кред(ов) -> %s":                 "[+] %d creds -> %s",
	"blob → пароль":                         "blob → password",
	"вставь base64 blob":                    "paste base64 blob",
	"   пароль: ":                           "   password: ",
	"префиксы":                              "prefixes",
	"IP цели или файл со списком хостов":    "target IP or host list file",
	"порт":                                  "port",
	"выходной файл (база, без расширения)":  "output file (base, no extension)",
	"[-] файл без хостов :(":                "[-] file has no hosts :(",
	"[+] серийников: %d, префиксов: %d":     "[+] serials: %d, prefixes: %d",
	"[+] серийников: %d, после фильтра: %d, префиксов: %d": "[+] serials: %d, after filter: %d, prefixes: %d",
	"фильтр моделей (через запятую, пусто = все)": "model filter (comma-separated, empty = all)",
	"  модель: ":                            "  model: ",
	"  прошивка: ":                          "  firmware: ",

	// ── фатальные файловые ошибки (красный диалог + sudo + проводник) ──
	"исправить права через sudo и повторить":               "fix permissions with sudo and retry",
	"выбрать другой путь (проводник)":                      "choose another path (file dialog)",
	"пароль sudo (пусто — если тикет свежий)":              "sudo password (empty if ticket is fresh)",
	"выбор отменён":                                        "selection cancelled",
	"подсказка: запусти крушитель от имени администратора": "hint: run krushitel as administrator",
	"[!] отмена.":                                          "[!] cancelled.",

	// ── экран прогона ──
	"[+] готово":  "[+] done",
	"%.1f/сек":    "%.1f/sec",
	"%.0f/сек":    "%.0f/sec",
	"%d/%d хостов": "%d/%d hosts",
	"найдено SN: %s": "found SNs: %s",
	"esc/b — стоп и в меню  ·  q — выход": "esc/b — stop & menu  ·  q — quit",
	"esc/b — в меню  ·  q — выход":        "esc/b — menu  ·  q — quit",
	"туннель: переподключение (попытка %d)": "tunnel: reconnecting (attempt %d)",
	"туннель поднят с %d-й попытки":         "tunnel up on attempt %d",
	"туннель: попытка %d не удалась (%v)":   "tunnel: attempt %d failed (%v)",

	// ── движок exploit ──
	"ошибка чтения входного файла: ":      "input file read error: ",
	"ошибка открытия входного файла: ":    "input file open error: ",
	"ошибка создания выходного файла: ":   "output file creation error: ",
	"ошибка открытия results.csv: ":       "results.csv open error: ",
	"ошибка открытия done.txt: ":          "done.txt open error: ",
	"ошибка открытия nostun.txt: ":        "nostun.txt open error: ",
	"ошибка создания папки результатов: ": "results folder creation error: ",
	"[+] xml-импорт в папку: ":              "xml import dir: ",
	"[!] xml-импорт выключен: ":             "xml import disabled: ",
	"[!] xml-запись не удалась: ":           "xml write failed: ",
	"Файл пуст":                             "file is empty",
	"креды юзера: ":                         "user creds: ",
	"логин: длина %d, нужно 5-32":           "login: length %d, need 5-32",
	"логин: только латиница и цифры":        "login: latin and digits only",
	"пароль: длина %d, нужно 8-32":          "password: length %d, need 8-32",
	"пароль: только латиница и цифры":       "password: latin and digits only",
	"туннель ✓":                             "tunnel ✓",
	"%s — туннель ок":                       "%s — tunnel ok",
	"%s — туннель ок (прямой путь)":         "%s — tunnel ok (direct path)",
	"%s — туннель ок (релей, может быть нестабилен)": "%s — tunnel ok (relay, may be unstable)",
	"%s — пробуем CVE-2021-33045 DHIP":      "%s — trying CVE-2021-33045 DHIP",
	"%s — пробуем CVE-2024-39943":           "%s — trying CVE-2024-39943",
	"%s — логин с помощью юзера":            "%s — creds failed check, trying user creds",
	"проверка кредов":                       "creds check",
	"%s — PWNED (%s) %s:%s":                 "%s — PWNED (%s) %s:%s",
	"%s — PWNED (Type-1) %s:%s":             "%s — PWNED (Type-1) %s:%s",
	"%s — юзер добавлен %s:%s":              "%s — user added %s:%s",
	"%s — неуязвим":                         "%s — invulnerable",
	"%s — OSD (канал): %v":                  "%s — OSD (channel): %v",
	"%s — OSD: %q":                          "%s — OSD: %q",
	"%s — OSD (все каналы): %q":             "%s — OSD (all channels): %q",
	"%s — OSD: отправлены без подтверждения": "%s — OSD: sent unconfirmed",
	"%s — OSD: %v":                          "%s — OSD: %v",
	"%s — снап не вышел: %s":                "%s — snap failed: %s",
	"%s — снап не вышел: порты 80, 5000, 37777 и 554 недоступны": "%s — snap failed: ports 80, 5000, 37777 and 554 unreachable",
	"%s — снап сохранён":                    "%s — snapshot saved",
	"%s — подключение через relay":          "%s — connecting via relay",
	"%s — порты из Info: http=%d priv=%d rtsp=%d": "%s — ports from Info: http=%d priv=%d rtsp=%d",
	"app relay сразу (%s)":                  "app relay immediately (%s)",
	"губернатор скорости (%s)":              "speed governor (%s)",
	"потолок pps: %s":                       "pps cap: %s",
	"авто":                                  "auto",
	"%s — вычистка юзеров: %v":              "%s — user wipe: %v",
	"%s — вычистка юзеров: лишних нет":      "%s — user wipe: nothing to delete",
	"%s — удалены юзеры: %s":                "%s — deleted users: %s",
	"[i] снапы/титры в работе: %d — esc прервёт всю работу": "[i] snaps/titles in progress: %d — esc will stop all the work",

	// ── подменю «титры по списку» ──
	"OSDChanger":                           "OSDChanger",
	"файл с камерами (results.txt)":        "cameras file (results.txt)",
	"[!] пропущено строк мимо формата: %d": "[!] skipped malformed lines: %d",
	"%s — offline (%v)":                    "%s — offline (%v)",
	"%s — offline (нулевой туннель)":       "%s — offline (empty tunnel)",
	"%s — ChannelTitle: %v - пробуем NetKeyboard": "%s — ChannelTitle: %v - trying NetKeyboard",
	"%s — ChannelTitle: не прошли (%v)":    "%s — ChannelTitle: failed (%v)",
	"%s — ChannelTitle: установлен":        "%s — ChannelTitle: applied",
	"титры: все поля пустые (настройки → тексты)": "titles: all fields empty (settings → texts)",

	// ── вне translate.md: код эмитит, в таблице нет ──
	"%s — устройство требует Type 1 auth": "%s — device requires Type 1 auth",
	"%s — нет ответа за %v — из очереди исключён": "%s — no answer for %v — excluded from queue",
	"%s — исчерпан (%d туннель-подъёма за прогон)": "%s — exhausted (%d tunnel attempts this run)",
	"%s — туннель не встал (%v) — в ре-очередь (попытка %d/%d)": "%s — tunnel failed (%v) — re-queued (attempt %d/%d)",
	"ре-очередь: запуск 2-го круга для %d недоступных серийников": "re-queue: second pass for %d unreachable serials",
	"autogen .xml (%s)": "autogen .xml (%s)",
	"по дефолту/by default: krushitel:TancuiPantera1337": "by default: krushitel:TancuiPantera1337",
	"ломаем":  "pwn some cams",
	"ломаем)": "pwn some cams)",
	"прерванный прогон (%s): отработано %d, осталось %d. продолжить с оставшихся? (нет = заново)": "interrupted run (%s): %d done, %d left. continue from the rest? (no = restart)",
	"прерванный прогон (%s): отработано %d. продолжить? (нет = заново)": "interrupted run (%s): %d done. continue? (no = restart)",
	"логи": "logs",

	// ── движок scanner ──
	"пинг %s — ок":                        "ping %s — ok",
	"автоподбор: установлено воркеров %d": "auto-tuning: %d workers set",
	"ошибка резолва сервера: ":                                            "server resolve error: ",
	"не смог создать сокеты (фикс: ":                                      "couldn't create sockets (fix: ",
	"подними лимит вручную: ":                                             "raise the fd limit manually: ",
	"дедуп-окно переполнено %d раз(а) — дубли могли уйти в повторный проб": "dedup window overflowed %d time(s) — dupes may have rescanned",
	"читаю файл…":    "reading file…",
	"серийников: %s": "serials: %s",
	"%d строк":       "%d lines",
	"МБ":             "MB",
	"%.0f/мин":       "%.0f/min",

	// ── discord rpc ──
	"сканит камеры через крушитель v%s": "scanning cam's with krushitel v%s",
	"в меню":                            "in menu",
	"discord rpc (%s)":                  "discord rpc (%s)",

	// ── автообновление ──
	"обновление":                              "update",
	"доступна новая версия: v%s (у тебя v%s)": "new version available: v%s (you have v%s)",
	"обновить":                                "update",
	"позже":                                   "later",
	"качаю обновление...":                     "downloading update...",
	"применяю обновление...":                  "applying update...",
	"перезапускаюсь...":                       "restarting...",
	"не вышло обновиться: %v":                 "update failed: %v",
	"enter — дальше":                          "enter — continue",
	"esc — отмена · q — выход":                "esc — cancel · q — quit",

	// ── двухфазный режим (скан в RAM → ломаем) ──
	"resume: пропускаю %d уже отскормленных серийников":     "resume: skipping %d already fed serials",
	"чекпоинт скана: продолжаю с %d (найдено %d, краш %s)":  "scan checkpoint: resuming from %d (found %d, crashed %s)",
	"скан уже готов (%s): %d серийников":                    "scan already done (%s): %d serials",
	"скан закончен: найдено %d":                             "scan finished: found %d",
	"resume: %d уже отработано":                             "resume: %d already done",
	"уже в %s: %d — пропускаю":                              "already in %s: %d — skipping",
	"всё отсканировано":                                     "all targets already done",
	"нет префиксов (>=10 символов) или серийников":          "no prefixes (>=10 chars) or serials found",
	"[1/2] сканируем %d серийников":                         "[1/2] scanning %d serials",
	"[2/2] ломаем %d серийников":                            "[2/2] pwning %d serials",
	"%d префикс(ов) | %d серийников на входе · //%s":        "%d prefix(es) | %d serials on input · //%s",
	"%d серийников на входе · //%s":                         "%d serials on input · //%s",
	"префикс или файл (префиксы/серийники)":                 "prefix or file (prefixes/serials)",
	"чекпоинт от другого файла! сканим с нуля":              "checkpoint is for another file! scanning from scratch",

	// ── хелп -h (headless) ──
	"Файл с серийниками/префиксами":                                      "File with SNs/prefixes",
	"Режимы работы  (exploit (по умолчанию) | titles | ironscan)":        "Modes  (exploit (by default) | titles | ironscan)",
	"порт для ironscan (по умолчанию 37777)":                             "port for ironscan (37777 by default)",
	"папка куда выводятся результаты (по умолчанию - имя входного файла)": "folder with results (by default - name of input file)",
	"кол-во потоков (по умолчанию 30)":                                   "workers (30 by default)",
	"игнорировать session-маркер и done.txt":                             "ignore session-mark and done.txt",
	"Большинство параметров есть в config.json.":                         "config.json contains more parameters.",

	// ── краш-сплеш ──
	"Это бета версия":       "This is a beta",
	"нажми любую клавишу...": "press any key...",
}

// Tr — перевод строки по словарю; при ru (или отсутствии ключа) — как есть.
func Tr(s string) string {
	if lang == "en" {
		if v, ok := en[s]; ok {
			return v
		}
	}
	return s
}
