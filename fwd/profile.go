package fwd

import (
	"crypto/rand"
	"fmt"
)

// Профиль приложения: говорим диалектом стокового клиента SmartPSS
// (главный сервер easy4ipcloud, зашитая WSSE-пара, глаголы DHGET/DHPOST).
// Поддержка DMSS/Dolynk удалена из стабл-версии.

// appProfile захватывает облачный диалект одного стокового клиента.
// Нулевые поля означают «фича не проговаривается этим клиентом»
// (заголовки опущены, шаги пропущены) — что и есть легаси wire-формат
// для smartpss.
type appProfile struct {
	name        string
	mainServer  string // главный облачный сервер (резолюция серийника)
	mainPort    int    // порт главного облачного сервера
	wsseUser    string // WSSE-пара приложения, зашитая в клиент
	wsseUserKey string
	verbGet     string // DHGET vs NFGET
	verbPost    string // DHPOST vs NFPOST
	createdNow  func() string

	toUType  string // значение X-ToUType; пусто = заголовок не шлётся
	version  string // значение X-Version; пусто = заголовок не шлётся
	sversion string // значение X-Sversion; пусто = заголовок не шлётся

	// Диалект сериализации запросов. smartpss держит легаси-wire байты
	// dh-fwd (CSeq-first порядок заголовков, глобальный счётчик CSeq);
	// dmss зеркалит приложение (захват 2026-09-06): version-заголовки →
	// x-pcs-request-id → X-ToUType → CSeq → auth, и случайный
	// SIGNED-int32 CSeq на логический запрос. Живой A/B на dmss-облаке:
	// эта форма отвечала `100 Trying` + `200 Server Nat Info!` 3/3
	// сессии; легаси-форма (CSeq first + малое значение счётчика) ловила
	// 403 DevPwd_InvalidDigest при байт-корректной крипто тела — порядок
	// и значение расходятся вместе.
	appHeaderOrder bool
	randomCSeq     bool

	pcsRequestID      bool // x-pcs-request-id на p2p-channel запросах
	extendedBody      bool // DMSS-теги тела канала (NatValueT/Pid/ClientId/sVersion)
	channelRetransmit bool // ретрансмит в стиле приложения: та же идентичность, свежая крипто
	localChannel      bool // app-паритетный шаг GET /device/<SN>/local-channel
	autoSalt          bool // Type-1 RandSalt читается из Info-блоба устройства
	noRelayAuth       bool // data-канал БЕЗ 0x17/0x19 auth (релейный диалект приложения: STUN → SYNC → BIND/DATA)

	// relayAgentOptional: клиент никогда не аллоцирует TCP relay-агента
	// (dmss: ноль трафика /online/relay, /relay/agent и relay-channel в
	// захватах сессии — его data-путь это пробитый прямой канал поверх
	// главного облака, Policy p2p,udprelay). Тогда диспетчерские обмены
	// идут BEST-EFFORT с коротким ограниченным чтением
	// (relayLookupTimeout / relayAgentTimeout): мёртвый диспетчер пишет в
	// лог, и хендшейк продолжается без стадии агента вместо блокировки на
	// полный RELAY_READ_TIMEOUT за чтение и рестарт-лупа (live
	// 2026-09-06: dolynk-диспетчер отвечал /relay/agent молчанием,
	// 17 с × 3).
	relayAgentOptional bool

	warmupPath string // первый облачный проб перед /online/p2psrv/<SN>
	warmupAuth bool   // несёт ли warm-up проб WSSE auth
}

var smartpssProfile = &appProfile{
	name:        "smartpss",
	mainServer:  MAIN_SERVER,
	mainPort:    MAIN_PORT,
	wsseUser:    WSSE_USERNAME,
	wsseUserKey: WSSE_USERKEY,
	verbGet:     "DHGET",
	verbPost:    "DHPOST",
	// Легаси-формат: UTC с литеральной Z, скорректированный по часам
	// облака (clock sync krushitel'а — WSSE Created должен совпадать с
	// серверным временем, иначе 401 TimeOut на уехавших часах).
	createdNow: func() string { return nowUTC().Format("2006-01-02T15:04:05Z") },
	warmupPath: "/probe/p2psrv",
	warmupAuth: true,
	channelRetransmit: true,
}

// Активный профиль пакета — всегда smartpss (поддержка DMSS удалена).
var activeProfile = smartpssProfile

// ActiveProfile возвращает текущий профиль облака.
func ActiveProfile() *appProfile { return activeProfile }

// SetProfile оставлен для совместимости конфигов: принимает только "smartpss".
func SetProfile(name string) error {
	if name != "" && name != "smartpss" {
		return fmt.Errorf("unknown app profile %q (only smartpss supported)", name)
	}
	activeProfile = smartpssProfile
	return nil
}

// profileByName резолвит профиль: только smartpss.
func profileByName(name string) (*appProfile, error) {
	if name == "" || name == "smartpss" {
		return smartpssProfile, nil
	}
	return nil, fmt.Errorf("unknown app profile %q (only smartpss supported)", name)
}

// randomHex отдаёт n крипто-случайных байт как 2n lowercase hex — формат
// x-pcs-request-id и ClientId session id приложения DMSS.
func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}
