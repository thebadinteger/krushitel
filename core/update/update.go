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

const CurrentVersion = "1.4"

const (
	repoOwner = "undervolter"
	repoName  = "krushitel"
)

const CheckTimeout = 10 * time.Second

var apiBase = "https://api.github.com"

type Release struct {
	Version string
	Tag     string
	Notes   string
	Asset   string
	URL     string
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

const (
	StageDL    = "dl"
	StageApply = "apply"
	StageDone  = "done"
	StageErr   = "err"
)

type Status struct {
	mu         sync.Mutex
	Stage      string
	Done       int64
	Total      int64
	Err        error
	Finished   bool
	HaveUpdate bool
}

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

func (s *Status) Snap() (string, int64, int64, error, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Stage, s.Done, s.Total, s.Err, s.Finished
}

type countReader struct {
	r  io.Reader
	n  *int64
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
	_ = os.Remove(oldPath)
	if err := os.Rename(exe, oldPath); err != nil {
		os.Remove(newPath)
		return fmt.Errorf("не отдал бинарник: %v", err)
	}
	if err := os.Rename(newPath, exe); err != nil {
		_ = os.Rename(oldPath, exe)
		return fmt.Errorf("не встал новый бинарник: %v", err)
	}
	return nil
}

func Sweep() {
	if exe, err := os.Executable(); err == nil {
		os.Remove(exe + ".old")
		os.Remove(exe + ".new")
	}
}

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
