package ui

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

type fieldKind int

const (
	fStr  fieldKind = iota // текст с валидацией
	fInt                   // целое с дефолтом
	fBool                  // y/n подтверждение
)

type formField struct {
	kind     fieldKind
	label    string
	def      string              // для fInt
	validate func(string) string // для fStr
	pass     bool                // маскировать ввод и ответ (пароли)
	input    textinput.Model
	strVal   string
	intVal   int
	boolVal  bool
}

// formState — последовательные промпты: текущий вопрос внизу списка,
// отвеченные — приглушённо со значениями. Реплика promptR/confirmYN.
type formState struct {
	panel  string // заголовок режима ("крушим")
	desc   string // красная строка под заголовком (фатальные диалоги)
	fields []formField
	cur    int
	errMsg string
	onDone func(m *model)
}

func newFormState(panel string, onDone func(m *model)) *formState {
	return &formState{panel: panel, onDone: onDone}
}

// addStr/addInt/addBool — конструкторы полей.
func (f *formState) addStr(label string, required bool, fileMustExist bool) {
	v := func(s string) string {
		if required && s == "" {
			return tr("обязательное поле")
		}
		if fileMustExist && !fileExists(s) {
			return tr("такого файла нет! перепиши, пожалуйста")
		}
		return ""
	}
	ti := textinput.New()
	ti.CharLimit = 512
	ti.Width = 60
	f.fields = append(f.fields, formField{kind: fStr, label: label, validate: v, input: ti})
}

func (f *formState) addInt(label string, def int) {
	ti := textinput.New()
	ti.CharLimit = 12
	ti.Width = 20
	ti.SetValue(fmt.Sprintf("%d", def))
	f.fields = append(f.fields, formField{kind: fInt, label: label, def: fmt.Sprintf("%d", def), intVal: def, input: ti})
}

// addPass — строка с маскировкой (пароль sudo): ввод точками, отвеченное
// значение на экране тоже маской, в strVal — как есть.
func (f *formState) addPass(label string) {
	ti := textinput.New()
	ti.CharLimit = 256
	ti.Width = 40
	ti.EchoMode = textinput.EchoPassword
	f.fields = append(f.fields, formField{kind: fStr, label: label, pass: true,
		validate: func(string) string { return "" }, input: ti})
}

func (f *formState) addBool(label string, def bool) {
	f.fields = append(f.fields, formField{kind: fBool, label: label, boolVal: def})
}

// focus — включить фокус текущего поля (str/int).
func (f *formState) focus() {
	for i := range f.fields {
		f.fields[i].input.Blur()
	}
	if f.cur < len(f.fields) && f.fields[f.cur].kind != fBool {
		f.fields[f.cur].input.Focus()
	}
}

// update — обработка клавиш; true = событие съедено формой.
// curIsBool — текущее поле — да/нет (текст не набирается, q безопасен).
func (f *formState) curIsBool() bool {
	return f != nil && f.cur < len(f.fields) && f.fields[f.cur].kind == fBool
}

// helpLine — подсказка снизу: зависит от типа текущего поля. На текстовых
// полях q — символ ввода, поэтому там выход только по ctrl+c.
func (f *formState) helpLine() string {
	if f.curIsBool() {
		return tr("y/n — да/нет · enter — далее · q — выход · esc — в меню")
	}
	return tr("enter — далее · esc — в меню · ctrl+c — выход")
}

func (f *formState) update(m *model, msg tea.KeyMsg) bool {
	if f.cur >= len(f.fields) {
		return false
	}
	fld := &f.fields[f.cur]

	switch msg.String() {
	case "enter":
		switch fld.kind {
		case fStr, fInt:
			val := strings.TrimSpace(fld.input.Value())
			if fld.kind == fStr {
				if errMsg := fld.validate(val); errMsg != "" {
					f.errMsg = errMsg
					return true
				}
				fld.strVal = val
			} else {
				n, err := strconv.Atoi(val)
				if err != nil || n < 1 {
					n, _ = strconv.Atoi(fld.def)
				}
				fld.intVal = n
			}
			f.next(m)
			return true
		case fBool:
			f.next(m)
			return true
		}

	case "y", "Y", "н", "Н":
		if fld.kind == fBool {
			fld.boolVal = true
			f.next(m)
			return true
		}

	case "n", "N", "т", "Т":
		if fld.kind == fBool {
			fld.boolVal = false
			f.next(m)
			return true
		}

	case " ":
		if fld.kind == fBool {
			fld.boolVal = !fld.boolVal
			return true
		}
	}

	if fld.kind != fBool {
		var cmd tea.Cmd
		fld.input, cmd = fld.input.Update(msg)
		_ = cmd
	}
	return true
}

// next — следующий вопрос или onDone.
func (f *formState) next(m *model) {
	f.errMsg = ""
	f.cur++
	if f.cur >= len(f.fields) {
		f.onDone(m)
		return
	}
	f.focus()
}

// view — баннер + панель + список ответов + текущий вопрос.
func (f *formState) view() string {
	var sb strings.Builder
	sb.WriteString(bannerBlock())
	sb.WriteString(strings.Repeat("\n", 4)) // шапка ниже баннера
	sb.WriteString(panelS(f.panel) + "\n\n")
	if f.desc != "" {
		// красная строка фатального диалога (многострочность — по \n)
		for _, ln := range strings.Split(f.desc, "\n") {
			sb.WriteString(centerLine(red(ln)) + "\n")
		}
		sb.WriteString("\n")
	}

	for i := 0; i <= f.cur && i < len(f.fields); i++ {
		fld := &f.fields[i]
		switch {
		case i < f.cur || (i == f.cur && f.cur >= len(f.fields)):
			// отвечено
			var val string
			switch fld.kind {
			case fBool:
				val = onOff(fld.boolVal)
			case fInt:
				val = strconv.Itoa(fld.intVal)
			default:
				if fld.pass {
					// пароль на экране не светим даже отвеченный
					if fld.strVal == "" {
						val = dim(tr("(пусто)"))
					} else {
						val = "••••••"
					}
				} else {
					val = fld.strVal
				}
			}
			sb.WriteString(centerLine(dim(fmt.Sprintf("%s: %s ✓", fld.label, val))) + "\n")
		case i == f.cur:
			switch fld.kind {
		case fBool:
			label := cyan(fld.label) + " (y/n)"
			if fld.boolVal {
				label += " " + green(tr("[да]"))
			} else {
				label += " " + red(tr("[нет]"))
			}
			sb.WriteString(centerLine(label) + "\n")
			case fInt:
				sb.WriteString(centerLine(cyan(fmt.Sprintf("%s [%s]", fld.label, fld.def))+": "+fld.input.View()) + "\n")
			default:
				sb.WriteString(centerLine(cyan(fld.label)+": "+fld.input.View()) + "\n")
			}
		}
	}

	if f.errMsg != "" {
		sb.WriteString("\n" + centerLine(red("↑ "+f.errMsg)) + "\n")
	}
	return sb.String()
}

func fileExists(s string) bool {
	st, err := os.Stat(s)
	return err == nil && !st.IsDir()
}

func onOff(b bool) string {
	if b {
		return tr("вкл")
	}
	return tr("выкл")
}
