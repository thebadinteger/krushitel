// Package update — автообновление через GitHub releases.
//
// Схема релиза (её же генерит build_release.ps1):
//   тег vX.Y.Z, ассеты krushitel_X.Y.Z_<goos>_<goarch>.zip,
//   внутри зипа один экзешник (имя не важно).
//
// Флоу: Check при старте (короткий таймаут, без сети молчим) →
// вопрос y/n в TUI → Install в фоне (прогресс в St для тика) →
// подмена бинарника rename-трюком (на винде переименование запущенного
// exe разрешено, перезапись — нет) → рестарт новым процессом.
package update

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CurrentVersion — единственный источник версии софта. Сюда смотрят
// RPC-строки, баннер, краш-сплеш и проверка обновлений; build_release.ps1
// забирает её же для имён архивов.
const CurrentVersion = "1.4"

const (
	repoOwner = "undervolter"
	repoName  = "krushitel"
)

// CheckTimeout — проверка при старте дольше не висит: без сети
// стартуем как обычно, без вопросов.
const CheckTimeout = 10 * time.Second

// apiBase — база GitHub API. Переменная (не константа), чтобы тесты могли
// подсунуть локальный фейк-сервер для симуляций. В бою перебивается
// только через env KRUSHITEL_UPDATE_API (для ручных прогонов e2e).
var apiBase = "https://api.github.com"

// Release — свежий релиз, подходящий под текущую платформу.
type Release struct {
	Version string // "1.4.0", без v
	Tag     string // "v1.4.0"
	Notes   string // body релиза
	Asset   string // имя zip-ассета
	URL     string // прямая ссылка на скачивание
	Size    int64
}

type ghRelease struct {
	TagName string    `json:"tag_name"`
	Body    string    `json:"body"`
	Assets  []ghAsset `json:"assets"`
}

type ghAsset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
	Size int64  `json:"size"`
}

var httpClient = &http.Client{Timeout: 60 * time.Second}

// Check — есть ли релиз новее текущего под нашу платформу.
// (nil, nil) = не надо обновляться, нет сети, rate limit, нет сборки
// под платформу — во всех случаях стартуем молча как обычно.
func Check(ctx context.Context) (*Release, error) {
	base := apiBase
	if env := os.Getenv("KRUSHITEL_UPDATE_API"); env != "" {
		base = strings.TrimRight(env, "/")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		base+"/repos/"+repoOwner+"/"+repoName+"/releases/latest", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "krushitel-updater")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}
	var gr ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&gr); err != nil {
		return nil, err
	}
	ver := strings.TrimSpace(gr.TagName)
	ver = strings.TrimPrefix(ver, "v")
	if ver == "" || !newerThan(ver, CurrentVersion) {
		return nil, nil
	}
	want := fmt.Sprintf("krushitel_%s_%s_%s.zip", ver, runtime.GOOS, runtime.GOARCH)
	for _, a := range gr.Assets {
		if a.Name == want && a.URL != "" {
			return &Release{Version: ver, Tag: gr.TagName, Notes: gr.Body,
				Asset: a.Name, URL: a.URL, Size: a.Size}, nil
		}
	}
	return nil, nil
}

// newerThan — строго новее по числовым кускам (1.4 > 1.3.9, 1.3.0 == 1.3).
// Суффиксы (-rc1) и мета (+build) отрезаем, без внешних либ.
func newerThan(v1, v2 string) bool {
	p1, p2 := parseVer(v1), parseVer(v2)
	n := len(p1)
	if len(p2) > n {
		n = len(p2)
	}
	for i := 0; i < n; i++ {
		var a, b int
		if i < len(p1) {
			a = p1[i]
		}
		if i < len(p2) {
			b = p2[i]
		}
		if a != b {
			return a > b
		}
	}
	return false
}

func parseVer(s string) []int {
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	var out []int
	for _, p := range strings.Split(s, ".") {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			return out
		}
		out = append(out, n)
	}
	return out
}

// ── прогресс для TUI ─────────────────────────────────────────────

// Stage'ы статуса установки.
const (
	StageDL    = "dl"    // качаем
	StageApply = "apply" // подменяем бинарник
	StageDone  = "done"  // готово, можно рестартовать
	StageErr   = "err"   // упали, в Err причина
)

// Status — прогресс Install, TUI поллит тиком. Пишет только воркер.
type Status struct {
	mu         sync.Mutex
	Stage      string
	Done       int64
	Total      int64
	Err        error
	Finished   bool
	HaveUpdate bool // St сброшен под новый Install
}

// St — глобальный статус текущей установки.
var St Status

func (s *Status) reset(total int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Stage = StageDL
	s.Done = 0
	s.Total = total
	s.Err = nil
	s.Finished = false
	s.HaveUpdate = true
}

func (s *Status) progress(n int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Done = n
}

func (s *Status) setStage(stage string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Stage = stage
}

func (s *Status) fail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Stage = StageErr
	s.Err = err
	s.Finished = true
}

func (s *Status) finish() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Stage = StageDone
	s.Finished = true
}

// Snap — срез для отрисовки (stage, done, total, err, finished).
func (s *Status) Snap() (string, int64, int64, error, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Stage, s.Done, s.Total, s.Err, s.Finished
}

// countReader — считает скачанное для прогресса.
type countReader struct {
	r io.Reader
	n *int64
	st *Status
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		*c.n += int64(n)
		c.st.progress(*c.n)
	}
	return n, err
}

// Install — скачать релиз и подменить бинарник. Блокирующая, запускать
// в горутине; прогресс и итог — в St. Контекст = отмена по Esc в TUI.
func Install(ctx context.Context, rel *Release) {
	St.reset(rel.Size)
	tmp, err := download(ctx, rel)
	if err != nil {
		St.fail(err)
		return
	}
	defer os.Remove(tmp)
	St.setStage(StageApply)
	if err := apply(tmp); err != nil {
		St.fail(err)
		return
	}
	St.finish()
}

// download — zip релиза во временный файл.
func download(ctx context.Context, rel *Release) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rel.URL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "krushitel-updater")
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("http %d", resp.StatusCode)
	}
	if resp.ContentLength > 0 {
		St.mu.Lock()
		St.Total = resp.ContentLength
		St.mu.Unlock()
	}
	tmp, err := os.CreateTemp("", "krushitel-upd-*.zip")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	var n int64
	_, err = io.Copy(tmp, &countReader{r: resp.Body, n: &n, st: &St})
	if cerr := tmp.Close(); cerr != nil && err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmpName)
		if ctx.Err() != nil {
			return "", fmt.Errorf("отменено")
		}
		return "", err
	}
	return tmpName, nil
}

// apply — распаковать exe из зипа и подменить текущий бинарник.
// Переименование запущенного exe разрешено и на винде, перезапись —
// нет, поэтому: .new рядом → exe в .old → .new в exe. С ошибкой на
// втором шаге — откат .old обратно.
func apply(zipPath string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer zr.Close()
	var entry *zip.File
	for _, f := range zr.File {
		if !f.FileInfo().IsDir() {
			entry = f
			break
		}
	}
	if entry == nil {
		return fmt.Errorf("в архиве нет файлов")
	}
	rc, err := entry.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	newPath := exe + ".new"
	oldPath := exe + ".old"
	out, err := os.OpenFile(newPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, rc)
	if cerr := out.Close(); cerr != nil && err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(newPath)
		return err
	}
	_ = os.Chmod(newPath, 0o755)
	_ = os.Remove(oldPath) // stale от прошлого раза
	if err := os.Rename(exe, oldPath); err != nil {
		os.Remove(newPath)
		return fmt.Errorf("не отдал бинарник: %v", err)
	}
	if err := os.Rename(newPath, exe); err != nil {
		_ = os.Rename(oldPath, exe) // откат
		return fmt.Errorf("не встал новый бинарник: %v", err)
	}
	return nil
}

// Sweep — убрать хвосты подмены (.old после рестарта, .new после обрыва).
// Вызывать при старте до Check.
func Sweep() {
	if exe, err := os.Executable(); err == nil {
		os.Remove(exe + ".old")
		os.Remove(exe + ".new")
	}
}

// Restart — запустить свежий бинарник с теми же аргументами.
// stdout/stderr передаём явно: к моменту рестарта TUI уже подменил
// os.Stdout на devnull. Возвращает после Start, вызыватель гасит себя.
func Restart(stdout, stderr *os.File) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	c := exec.Command(exe, os.Args[1:]...)
	c.Stdin = os.Stdin
	c.Stdout = stdout
	c.Stderr = stderr
	return c.Start()
}
