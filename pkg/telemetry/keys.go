package telemetry

import "github.com/charmbracelet/bubbles/key"

type keyMap struct {
	Up         key.Binding
	Down       key.Binding
	Left       key.Binding
	Right      key.Binding
	Tab        key.Binding
	Enter      key.Binding
	Maximize   key.Binding
	ToggleTree key.Binding
	Pause      key.Binding
	Help       key.Binding
	NextPage   key.Binding
	PrevPage   key.Binding
	Esc        key.Binding
	Quit       key.Binding
	Search     key.Binding
}

func (k keyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Tab, k.Maximize, k.Enter, k.Help, k.Quit}
}

func (k keyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Up, k.Down, k.Left, k.Right},
		{k.Tab, k.Maximize, k.Enter, k.ToggleTree},
		{k.NextPage, k.PrevPage, k.Pause, k.Search},
		{k.Help, k.Esc, k.Quit},
	}
}

var keys = keyMap{
	Up:         key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("↑/k", "navigate")),
	Down:       key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("↓/j", "navigate")),
	Left:       key.NewBinding(key.WithKeys("left", "h"), key.WithHelp("←/h", "collapse branch")),
	Right:      key.NewBinding(key.WithKeys("right", "l"), key.WithHelp("→/l", "expand branch")),
	Tab:        key.NewBinding(key.WithKeys("tab"), key.WithHelp("tab", "cycle pane")),
	Enter:      key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "inspect event")),
	Maximize:   key.NewBinding(key.WithKeys("m"), key.WithHelp("m", "maximize/restore")),
	ToggleTree: key.NewBinding(key.WithKeys("e"), key.WithHelp("e", "expand/collapse all")),
	Pause:      key.NewBinding(key.WithKeys("p", " "), key.WithHelp("p/space", "pause/resume")),
	Help:       key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "help")),
	NextPage:   key.NewBinding(key.WithKeys("]"), key.WithHelp("]", "next page")),
	PrevPage:   key.NewBinding(key.WithKeys("["), key.WithHelp("[", "prev page")),
	Esc:        key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "back/cancel")),
	Quit:       key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
	Search:     key.NewBinding(key.WithKeys("/"), key.WithHelp("/", "filter")),
}
