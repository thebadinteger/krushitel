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

func isSSH() bool {
	return os.Getenv("SSH_CONNECTION") != "" ||
		os.Getenv("SSH_CLIENT") != "" ||
		os.Getenv("SSH_TTY") != ""
}

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

func hasSudo() bool {
	if runtime.GOOS == "windows" {
		return false
	}
	_, err := exec.LookPath("sudo")
	return err == nil
}

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

func openConsole() (*os.File, error) {
	if runtime.GOOS == "windows" {
		return os.OpenFile("CON", os.O_RDWR, 0)
	}
	return os.OpenFile("/dev/tty", os.O_RDWR, 0)
}

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

var ErrSudoNoTTY = errors.New("sudo requires tty")

func SudoCached() bool {
	if runtime.GOOS == "windows" {
		return false
	}
	return exec.Command("sudo", "-n", "true").Run() == nil
}

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

func psEscape(s string) string { return strings.ReplaceAll(s, "'", "''") }

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

func preflightOutFile(outFile string) error {
	if err := preflightDir(filepath.Dir(outFile)); err != nil {
		return err
	}
	if st, err := os.Stat(outFile); err == nil && st.IsDir() {
		return fmt.Errorf("open %s: is a directory", outFile)
	}
	return nil
}

func fatalFieldPlan(triedSudo bool, err error) (showSudo, showPicker bool) {
	showSudo = !triedSudo && hasSudo() && isPermissionErr(err)
	showPicker = hasGUI()
	return showSudo, showPicker
}
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
	if !showSudo && !showPicker {
		showMsg(m, title, red(errText))
		return
	}
	m.form = f
	m.form.focus()
}
