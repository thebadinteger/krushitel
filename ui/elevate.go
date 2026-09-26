// elevate.go — фатальные файловые ошибки: красный диалог, sudo-ретрай,
// диалог сохранения через проводник.
//
// Правило №1 этого файла: всё, что трогает системный терминал (живой
// sudo-промпт, проводник), идёт через SuspendExec — TUI отпускает alt-screen
// и ридер ввода, после всё восстанавливается с перерисовкой. Без этого
// системная строка разъезжает интерфейс (см. ReleaseTerminal:
// гасит и ридер — пожирания клавиш нет; RestoreTerminal — перерисовывает).
package ui

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
)

// ── детект окружения ───────────────────────────────────────────────

// isSSH — сессия по SSH (проводника нет — только текстовый sudo-путь).
func isSSH() bool {
	return os.Getenv("SSH_CONNECTION") != "" ||
		os.Getenv("SSH_CLIENT") != "" ||
		os.Getenv("SSH_TTY") != ""
}

// hasGUI — есть кому показать оконный диалог сохранения.
// Windows: powershell-диалоги (кроме SSH-сессии). Unix: иксы/вейланд.
func hasGUI() bool {
	if isSSH() {
		return false
	}
	if runtime.GOOS == "windows" {
		_, err := exec.LookPath("powershell.exe")
		return err == nil
	}
	return os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != ""
}

// hasSudo — есть чем повышаться (не-Windows + бинарь на месте).
func hasSudo() bool {
	if runtime.GOOS == "windows" {
		return false
	}
	_, err := exec.LookPath("sudo")
	return err == nil
}

// ── саспенд ────────────────────────────────────────────────────────

// SuspendExec выполняет fn с живым терминалом: отпускаем alt-screen и ридер
// ввода, после — восстанавливаем с перерисовкой. Вне запущенного TUI
// (teaProg == nil, тесты) — просто выполняет fn.
func SuspendExec(fn func() error) error {
	if teaProg == nil {
		return fn()
	}
	if err := teaProg.ReleaseTerminal(); err != nil {
		return err
	}
	defer teaProg.RestoreTerminal()
	return fn()
}

// openConsole — живой терминал для дочернего процесса. Важно: os.Stdout
// у нас подменён на devnull, поэтому наследовать stdio нельзя — промпт
// станет невидимым. /dev/tty (CON на винде) — всегда настоящий терминал.
func openConsole() (*os.File, error) {
	if runtime.GOOS == "windows" {
		return os.OpenFile("CON", os.O_RDWR, 0)
	}
	return os.OpenFile("/dev/tty", os.O_RDWR, 0)
}

// ── классификация ошибок ───────────────────────────────────────────

// isPermissionErr — ошибка из семейства «нет прав / не туда пишем»:
// EACCES/EPERM через os.IsPermission (+маппинг Windows ERROR_ACCESS_DENIED),
// EISDIR/ENOTDIR/ROFS — текстовыми фолбэками (кроссплатформенно, без syscall).
// Именно сюда попадает и «mkdir: this is a directory».
func isPermissionErr(err error) bool {
	if err == nil {
		return false
	}
	if os.IsPermission(err) {
		return true
	}
	msg := strings.ToLower(err.Error())
	for _, s := range []string{
		"permission denied", "access is denied", "not permitted",
		"read-only", "readonly", "read only",
		"is a directory", "not a directory",
	} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

// ── sudo ───────────────────────────────────────────────────────────

// ErrSudoNoTTY — sudo требует живой терминал (requiretty/use_pty в sudoers):
// пароль через пайп не примет, только SuspendExec + настоящий промпт.
var ErrSudoNoTTY = errors.New("sudo requires tty")

// SudoCached — свежий ли sudo-тикет (sudo -n true без пароля).
// Тикет свежий почти всегда после первого ввода — тогда вообще без промптов.
func SudoCached() bool {
	if runtime.GOOS == "windows" {
		return false
	}
	return exec.Command("sudo", "-n", "true").Run() == nil
}

// SudoRun — выполнить команду через sudo. password "" = без пайпа
// (сработает при свежем тикете). stdout/stderr глушим в буферы — никакого
// мусора в TUI; текст ошибки возвращаем вызывателю.
func SudoRun(password, name string, args ...string) error {
	if runtime.GOOS == "windows" {
		return errors.New("no sudo on windows")
	}
	full := append([]string{"-S", "-p", "", name}, args...)
	cmd := exec.Command("sudo", full...)
	if password != "" {
		cmd.Stdin = strings.NewReader(password + "\n")
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		errText := strings.TrimSpace(stderr.String())
		if strings.Contains(errText, "no tty present") {
			return ErrSudoNoTTY
		}
		if errText != "" {
			if i := strings.IndexByte(errText, '\n'); i >= 0 {
				errText = errText[:i]
			}
			return fmt.Errorf("sudo: %s", errText)
		}
		return err
	}
	return nil
}

// SudoValidateLive — живой `sudo -v` на настоящем терминале (промпт пароля
// видит юзер). Только через SuspendExec + /dev/tty: наш stdout — devnull.
func SudoValidateLive() error {
	return SuspendExec(func() error {
		tty, err := openConsole()
		if err != nil {
			return err
		}
		defer tty.Close()
		cmd := exec.Command("sudo", "-v")
		cmd.Stdin, cmd.Stdout, cmd.Stderr = tty, tty, tty
		return cmd.Run()
	})
}

// currentUser — кому отдавать починенную папку (мы не рут, SUDO_USER пуст).
func currentUser() string {
	if u := os.Getenv("SUDO_USER"); u != "" {
		return u
	}
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	if u := os.Getenv("USERNAME"); u != "" {
		return u
	}
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return ""
}

// SudoFixDir — чинит EACCES раз и навсегда: mkdir -p + chown на текущего
// юзера (одноразовый sudo touch не лечит — движок всё равно не запишет).
func SudoFixDir(dir, password string) error {
	if err := SudoRun(password, "mkdir", "-p", dir); err != nil {
		return err
	}
	u := currentUser()
	if u == "" {
		return errors.New("no user to chown")
	}
	return SudoRun(password, "chown", u, dir)
}

// ── проводник ──────────────────────────────────────────────────────

// psEscape — экранирование для powershell-одинарных кавычек.
func psEscape(s string) string { return strings.ReplaceAll(s, "'", "''") }

// saveDialogCmd — команда нативного диалога сохранения.
// Возвращает ("", nil, false), если показать некому (SSH/консоль без GUI).
func saveDialogCmd(suggestedPath string) (string, []string, bool) {
	if !hasGUI() {
		return "", nil, false
	}
	if runtime.GOOS == "windows" {
		ps := fmt.Sprintf(
			`Add-Type -AssemblyName System.Windows.Forms; `+
				`$d = New-Object System.Windows.Forms.SaveFileDialog; `+
				`$d.InitialDirectory = '%s'; $d.FileName = '%s'; `+
				`$d.Filter = 'All files (*.*)|*.*'; `+
				`if ($d.ShowDialog() -eq 'OK') { $d.FileName }`,
			psEscape(filepath.Dir(suggestedPath)), psEscape(filepath.Base(suggestedPath)))
		return "powershell.exe", []string{"-NoProfile", "-STA", "-Command", ps}, true
	}
	if _, err := exec.LookPath("zenity"); err == nil {
		return "zenity", []string{"--file-selection", "--save", "--confirm-overwrite",
			"--filename=" + suggestedPath}, true
	}
	if _, err := exec.LookPath("kdialog"); err == nil {
		return "kdialog", []string{"--getsavefilename", suggestedPath}, true
	}
	return "", nil, false
}

// SaveDialog — путь из проводника ("" = отмена/некому показать).
// Всегда саспенд: диалог модальный, TUI в это время заморожен целиком.
func SaveDialog(suggestedPath string) string {
	name, args, ok := saveDialogCmd(suggestedPath)
	if !ok {
		return ""
	}
	var out bytes.Buffer
	_ = SuspendExec(func() error {
		cmd := exec.Command(name, args...)
		cmd.Stdout = &out
		return cmd.Run()
	})
	return strings.TrimSpace(out.String())
}

// saveDialogDirCmd — нативный выбор ПАПКИ (для режимов с outDir).
func saveDialogDirCmd(startDir string) (string, []string, bool) {
	if !hasGUI() {
		return "", nil, false
	}
	if runtime.GOOS == "windows" {
		ps := fmt.Sprintf(
			`Add-Type -AssemblyName System.Windows.Forms; `+
				`$d = New-Object System.Windows.Forms.FolderBrowserDialog; `+
				`$d.SelectedPath = '%s'; `+
				`if ($d.ShowDialog() -eq 'OK') { $d.SelectedPath }`,
			psEscape(startDir))
		return "powershell.exe", []string{"-NoProfile", "-STA", "-Command", ps}, true
	}
	if _, err := exec.LookPath("zenity"); err == nil {
		return "zenity", []string{"--file-selection", "--directory",
			"--filename=" + startDir}, true
	}
	if _, err := exec.LookPath("kdialog"); err == nil {
		return "kdialog", []string{"--getexistingdirectory", startDir}, true
	}
	return "", nil, false
}

// SaveDialogDir — папка из проводника ("" = отмена/некому показать).
func SaveDialogDir(startDir string) string {
	name, args, ok := saveDialogDirCmd(startDir)
	if !ok {
		return ""
	}
	var out bytes.Buffer
	_ = SuspendExec(func() error {
		cmd := exec.Command(name, args...)
		cmd.Stdout = &out
		return cmd.Run()
	})
	return strings.TrimSpace(out.String())
}

// ── префлайт ───────────────────────────────────────────────────────

// preflightDir — пробная запись в папку ДО запуска движка: MkdirAll +
// touch + remove. "" = писать можно. Ловит EACCES/EISDIR/EROFS заранее,
// а не посреди прогона.
//
// KRUSHITEL_FATAL_TEST=1 — тестовый крюк: префлайт всегда падает с фейковой
// EACCES, чтобы проверить красный диалог без реального сбоя (и без создания
// xml — движок вообще не стартует). Только для ручной проверки UI.
func preflightDir(dir string) error {
	if dir == "" {
		dir = "."
	}
	if os.Getenv("KRUSHITEL_FATAL_TEST") != "" {
		return fmt.Errorf("mkdir %s: permission denied (KRUSHITEL_FATAL_TEST)", dir)
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	probe := filepath.Join(dir, ".krushitel-write-test")
	if err := os.WriteFile(probe, []byte("ok"), 0644); err != nil {
		return err
	}
	_ = os.Remove(probe)
	return nil
}

// preflightOutFile — префлайт выходного ФАЙЛА: папка пишем + сам путь не
// папка. Ловит кейс «outFile существует как директория» (open 1337:
// is a directory) до старта движка — иначе падает уже движок с плоской
// строкой без диалога.
func preflightOutFile(outFile string) error {
	if err := preflightDir(filepath.Dir(outFile)); err != nil {
		return err
	}
	if st, err := os.Stat(outFile); err == nil && st.IsDir() {
		return fmt.Errorf("open %s: is a directory", outFile)
	}
	return nil
}

// ── красный диалог ─────────────────────────────────────────────────

// fatalFieldPlan — какие действия показать в красном диалоге.
// Чистая функция ради тестов: sudo — только unix + права + первый раз,
// проводник — только при GUI.
func fatalFieldPlan(triedSudo bool, err error) (showSudo, showPicker bool) {
	showSudo = !triedSudo && hasSudo() && isPermissionErr(err)
	showPicker = hasGUI()
	return showSudo, showPicker
}
// fatalFileDialog — красный диалог фатальной файловой ошибки.
// retry — повторить исходный запуск (после sudo-фикса).
// relaunch — запуск с другим путём (из проводника).
// dir — проблемная папка (sudo chown + стартовая точка проводника).
// triedSudo — sudo уже пробовали (защита от зацикливания диалога).
// pickDir — проводник выбирает папку (режимы с outDir), иначе файл.
func fatalFileDialog(m *model, title string, err error, dir string, triedSudo bool,
	pickDir bool, retry func(), relaunch func(newPath string)) {
	errText := err.Error()
	perm := isPermissionErr(err)
	showSudo, showPicker := fatalFieldPlan(triedSudo, err)

	f := newFormState(title, func(m *model) {
		i := 0
		var useSudo, wantPicker bool
		var pw string
		if showSudo {
			useSudo = m.form.fields[i].boolVal
			i++
		}
		if showPicker {
			wantPicker = m.form.fields[i].boolVal
			i++
		}
		if showSudo {
			pw = m.form.fields[i].strVal
		}
		if useSudo {
			if ferr := SudoFixDir(dir, pw); ferr != nil {
				if errors.Is(ferr, ErrSudoNoTTY) {
					// requiretty: живой промпт на настоящем терминале
					if verr := SudoValidateLive(); verr != nil {
						showMsg(m, title, red("[-] sudo: "+verr.Error()))
						return
					}
					if ferr = SudoFixDir(dir, ""); ferr != nil {
						showMsg(m, title, red("[-] sudo: "+ferr.Error()))
						return
					}
				} else {
					showMsg(m, title, red("[-] sudo: "+ferr.Error()))
					return
				}
			}
			retry()
			return
		}
		if wantPicker {
			var p string
			if pickDir {
				p = SaveDialogDir(dir)
			} else {
				p = SaveDialog(dir)
			}
			if p != "" {
				relaunch(p)
				return
			}
			showMsg(m, title, red(tr("выбор отменён")))
			return
		}
		showMsg(m, title, red(tr("[!] отмена.")))
	})
	var lines []string
	lines = append(lines, errText)
	if runtime.GOOS == "windows" && perm {
		lines = append(lines, tr("подсказка: запусти крушитель от имени администратора"))
	}
	f.desc = strings.Join(lines, "\n")

	if showSudo {
		f.addBool(tr("исправить права через sudo и повторить"), true)
	}
	if showPicker {
		f.addBool(tr("выбрать другой путь (проводник)"), false)
	}
	if showSudo {
		f.addPass(tr("пароль sudo (пусто — если тикет свежий)"))
	}
	// Безусловный минимум: диалог обязан иметь хоть одно поле,
	// иначе форма сразу провалится в onDone. Без действий —
	// просто красный текст (ветка недостижима: showMsg выше).
	if !showSudo && !showPicker {
		showMsg(m, title, red(errText))
		return
	}
	m.form = f
	m.form.focus()
}
