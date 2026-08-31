// SPDX-License-Identifier: Apache-2.0
package main

import (
	"database/sql"
	"fmt"
	"strings"
	"unicode/utf8"

	tea "github.com/charmbracelet/bubbletea"
)

// viewMode is which list the left pane shows. Chain is reached with 'c' (or
// enter on the Ready view) and returns to the previous view on esc.
type viewMode int

const (
	viewDAG viewMode = iota
	viewEpics
	viewReady
	viewChain
)

type rowKind int

const (
	rowTask rowKind = iota
	rowHeader
)

// row is one rendered line of the left pane. Task rows carry a stable
// expansion key — the slash-joined path of IDs from the view root — so the
// same task reached through two parents folds independently.
type row struct {
	kind    rowKind
	header  string // rowHeader only
	id      string
	depth   int
	key     string
	hasKids bool
	revisit bool // task already expanded earlier in this build; rendered as a ⤴ reference
	focal   bool // chain view: the centered task
}

// foldState is per-view folding: a default plus per-key exceptions, so
// expand-all / collapse-all are O(1) (flip the default, drop the exceptions).
type foldState struct {
	defaultExpanded bool
	toggled         map[string]bool
}

func (f *foldState) expanded(key string) bool { return f.defaultExpanded != f.toggled[key] }

func (f *foldState) set(key string, want bool) {
	if want != f.defaultExpanded {
		f.toggled[key] = true
	} else {
		delete(f.toggled, key)
	}
}

func (f *foldState) reset(def bool) {
	f.defaultExpanded = def
	f.toggled = map[string]bool{}
}

type tuiModel struct {
	db   *sql.DB
	snap *snapshot

	mode     viewMode
	prevMode viewMode // view to return to when leaving chain
	chainID  string   // focal task of chain view

	rows   []row
	cursor int
	offset int

	width, height int

	folds map[viewMode]*foldState

	statusFilter Status // "" = all
	search       string
	searching    bool // search input has focus

	detailScroll int
	showHelp     bool
	flash        string // one-shot footer message, cleared on next key
}

func newTUI(db *sql.DB, snap *snapshot, mode viewMode) *tuiModel {
	m := &tuiModel{
		db:       db,
		snap:     snap,
		mode:     mode,
		prevMode: mode,
		folds: map[viewMode]*foldState{
			viewDAG:   {defaultExpanded: true, toggled: map[string]bool{}},
			viewEpics: {defaultExpanded: true, toggled: map[string]bool{}},
			viewReady: {defaultExpanded: true, toggled: map[string]bool{}},
			viewChain: {defaultExpanded: true, toggled: map[string]bool{}},
		},
	}
	m.rebuild("")
	return m
}

func (m *tuiModel) Init() tea.Cmd { return nil }

func (m *tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.ensureVisible()
	case tea.MouseMsg:
		if msg.Action == tea.MouseActionPress {
			switch msg.Button {
			case tea.MouseButtonWheelUp:
				m.move(-3)
			case tea.MouseButtonWheelDown:
				m.move(3)
			}
		}
	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m *tuiModel) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	m.flash = ""

	// Runes that arrive in one read (paste, synthetic input) are batched into
	// a single KeyRunes message; outside the search box, replay them as
	// individual keypresses so "2g" still means '2' then 'g'.
	if !m.searching && msg.Type == tea.KeyRunes && !msg.Alt && len(msg.Runes) > 1 {
		var mod tea.Model = m
		var cmd tea.Cmd
		for _, r := range msg.Runes {
			mod, cmd = m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
			if cmd != nil {
				return mod, cmd // quit mid-batch: drop the rest
			}
			// Entering search mode consumes the remainder as search input —
			// matching what typing the same keys by hand would do — except we
			// just stop; replaying the tail into the box would be surprising.
			if m.searching {
				break
			}
		}
		return mod, cmd
	}

	if m.searching {
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit
		case "esc":
			m.searching = false
			m.search = ""
			m.rebuild(m.selectedID())
		case "enter":
			m.searching = false
		case "backspace":
			if m.search != "" {
				_, sz := utf8.DecodeLastRuneInString(m.search)
				m.search = m.search[:len(m.search)-sz]
				m.rebuild(m.selectedID())
			}
		default:
			if msg.Type == tea.KeyRunes {
				m.search += string(msg.Runes)
				m.rebuild(m.selectedID())
			}
		}
		return m, nil
	}

	if m.showHelp {
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		default:
			m.showHelp = false
		}
		return m, nil
	}

	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "?":
		m.showHelp = true
	case "1":
		m.switchMode(viewDAG)
	case "2":
		m.switchMode(viewEpics)
	case "3":
		m.switchMode(viewReady)
	case "tab":
		next := map[viewMode]viewMode{viewDAG: viewEpics, viewEpics: viewReady, viewReady: viewDAG, viewChain: m.prevMode}
		m.switchMode(next[m.mode])
	case "j", "down":
		m.move(1)
	case "k", "up":
		m.move(-1)
	case "g", "home":
		m.cursor = -1
		m.move(1)
	case "G", "end":
		m.cursor = len(m.rows)
		m.move(-1)
	case "ctrl+d", "pgdown":
		m.move(m.bodyHeight() / 2)
	case "ctrl+u", "pgup":
		m.move(-m.bodyHeight() / 2)
	case "J":
		m.detailScroll += 3 // clamped against content length at render time
	case "K":
		m.detailScroll = max(0, m.detailScroll-3)
	case "l", "right":
		m.setFold(true)
	case " ", "space":
		if r, ok := m.selectedRow(); ok && r.hasKids {
			m.setFold(!m.expandedNow(r.key))
		}
	case "enter":
		switch m.mode {
		case viewChain:
			m.openChain() // re-center on the selected task
		case viewReady:
			m.openChain()
		default:
			m.setFold(true)
		}
	case "h", "left":
		m.collapseOrParent()
	case "L":
		m.folds[m.mode].reset(true)
		m.rebuild(m.selectedID())
	case "H":
		m.folds[m.mode].reset(false)
		m.rebuild(m.selectedID())
	case "c":
		m.openChain()
	case "esc":
		switch {
		case m.search != "" || m.statusFilter != "":
			m.search = ""
			m.statusFilter = ""
			m.rebuild(m.selectedID())
		case m.mode == viewChain:
			m.mode = m.prevMode
			m.rebuild(m.chainID)
		}
	case "/":
		m.searching = true
	case "s":
		cycle := map[Status]Status{"": StatusOpen, StatusOpen: StatusInProgress, StatusInProgress: StatusBlocked, StatusBlocked: StatusDone, StatusDone: StatusDropped, StatusDropped: ""}
		m.statusFilter = cycle[m.statusFilter]
		m.rebuild(m.selectedID())
	case "r":
		snap, err := loadSnapshot(m.db)
		if err != nil {
			m.flash = "reload failed: " + err.Error()
		} else {
			m.snap = snap
			m.flash = fmt.Sprintf("reloaded %d tasks", len(snap.tasks))
			m.rebuild(m.selectedID())
		}
	}
	return m, nil
}

func (m *tuiModel) switchMode(mode viewMode) {
	if mode == m.mode {
		return
	}
	keep := m.selectedID()
	if m.mode == viewChain {
		keep = m.chainID
	}
	m.mode = mode
	m.rebuild(keep)
}

// openChain centers the chain view on the selected task.
func (m *tuiModel) openChain() {
	sel := m.selectedID()
	if sel == "" {
		return
	}
	if m.mode != viewChain {
		m.prevMode = m.mode
	}
	m.chainID = sel
	m.mode = viewChain
	m.folds[viewChain].reset(true)
	m.rebuild("")
}

// setFold expands or collapses the selected row.
func (m *tuiModel) setFold(want bool) {
	r, ok := m.selectedRow()
	if !ok || !r.hasKids {
		return
	}
	m.folds[m.mode].set(r.key, want)
	m.rebuild("")
	// Rebuilding may move the row; re-find it by key so the cursor stays put.
	for i, rr := range m.rows {
		if rr.kind == rowTask && rr.key == r.key {
			m.cursor = i
			break
		}
	}
	m.ensureVisible()
}

// collapseOrParent collapses an expanded node; on a leaf or an already
// collapsed node it jumps to the rendered parent (the nearest row above with
// a smaller depth), which makes h/h/h... walk up and fold a whole chain.
func (m *tuiModel) collapseOrParent() {
	r, ok := m.selectedRow()
	if !ok {
		return
	}
	if r.hasKids && m.expandedNow(r.key) && !m.filterActive() {
		m.setFold(false)
		return
	}
	for i := m.cursor - 1; i >= 0; i-- {
		if m.rows[i].kind == rowTask && m.rows[i].depth < r.depth {
			m.cursor = i
			m.detailScroll = 0
			m.ensureVisible()
			return
		}
	}
}

func (m *tuiModel) selectedRow() (row, bool) {
	if m.cursor >= 0 && m.cursor < len(m.rows) && m.rows[m.cursor].kind == rowTask {
		return m.rows[m.cursor], true
	}
	return row{}, false
}

func (m *tuiModel) selectedID() string {
	if r, ok := m.selectedRow(); ok {
		return r.id
	}
	return ""
}

// move advances the cursor by delta task rows, skipping headers.
func (m *tuiModel) move(delta int) {
	if len(m.rows) == 0 {
		m.cursor = 0
		return
	}
	dir := 1
	if delta < 0 {
		dir = -1
		delta = -delta
	}
	c := m.cursor
	for range delta {
		n := c + dir
		for n >= 0 && n < len(m.rows) && m.rows[n].kind != rowTask {
			n += dir
		}
		if n < 0 || n >= len(m.rows) {
			break
		}
		c = n
	}
	if c != m.cursor {
		m.cursor = c
		m.detailScroll = 0
	}
	m.ensureVisible()
}

func (m *tuiModel) ensureVisible() {
	h := m.bodyHeight()
	if m.cursor < m.offset {
		m.offset = m.cursor
	}
	if m.cursor >= m.offset+h {
		m.offset = m.cursor - h + 1
	}
	if m.offset > len(m.rows)-h {
		m.offset = len(m.rows) - h
	}
	if m.offset < 0 {
		m.offset = 0
	}
}

// bodyHeight is the list/detail height: total minus 2 header + 2 footer lines.
func (m *tuiModel) bodyHeight() int {
	return max(3, m.height-4)
}

func (m *tuiModel) filterActive() bool {
	return m.search != "" || m.statusFilter != ""
}

// expandedNow is the fold state with filters applied: an active filter
// force-expands everything so matches are never hidden inside a fold.
func (m *tuiModel) expandedNow(key string) bool {
	if m.filterActive() {
		return true
	}
	return m.folds[m.mode].expanded(key)
}

func (m *tuiModel) matches(t *Task) bool {
	if m.statusFilter != "" && t.Status != m.statusFilter {
		return false
	}
	return m.searchMatches(t)
}

func (m *tuiModel) searchMatches(t *Task) bool {
	if m.search == "" {
		return true
	}
	q := strings.ToLower(m.search)
	return strings.Contains(strings.ToLower(t.Title), q) || strings.Contains(strings.ToLower(t.ID), q)
}

// rebuild regenerates the row list for the current mode and restores the
// cursor: to `keep` when given, to the chain focal row in chain view,
// otherwise to the first task row.
func (m *tuiModel) rebuild(keep string) {
	switch m.mode {
	case viewDAG:
		m.rows = m.buildDAG()
	case viewEpics:
		m.rows = m.buildEpics()
	case viewReady:
		m.rows = m.buildReady()
	case viewChain:
		m.rows = m.buildChain()
	}

	m.cursor = 0
	found := false
	if m.mode == viewChain && keep == "" {
		for i, r := range m.rows {
			if r.focal {
				m.cursor, found = i, true
				break
			}
		}
	}
	if !found && keep != "" {
		for i, r := range m.rows {
			if r.kind == rowTask && r.id == keep {
				m.cursor, found = i, true
				break
			}
		}
	}
	if !found {
		m.cursor = -1
		m.move(1)
	}
	m.detailScroll = 0
	m.ensureVisible()
}

// dagInclude returns nil when no filter is active; otherwise the set of tasks
// to render: every match plus everything upstream of it (its transitive
// deps), which are exactly the render-tree ancestors in the DAG view.
func (m *tuiModel) dagInclude() map[string]bool {
	if !m.filterActive() {
		return nil
	}
	inc := map[string]bool{}
	var up func(id string)
	up = func(id string) {
		if inc[id] {
			return
		}
		inc[id] = true
		for _, d := range m.snap.deps[id] {
			up(d)
		}
	}
	for _, t := range m.snap.tasks {
		if m.matches(t) {
			up(t.ID)
		}
	}
	return inc
}

// buildDAG renders the dependency forest in execution order: roots are tasks
// with no dependencies, children are dependents (what finishing the parent
// unblocks). A task reachable through several parents is expanded only at its
// first occurrence; later occurrences are ⤴ references, which bounds the row
// count by tasks + edges.
func (m *tuiModel) buildDAG() []row {
	s := m.snap
	inc := m.dagInclude()

	var chains, singles []*Task
	for _, t := range s.tasks {
		if len(s.deps[t.ID]) > 0 {
			continue // not a root
		}
		if inc != nil && !inc[t.ID] {
			continue
		}
		if len(s.rdeps[t.ID]) > 0 {
			chains = append(chains, t)
		} else {
			singles = append(singles, t)
		}
	}

	var rows []row
	seen := map[string]bool{}
	var walk func(id string, depth int, path string)
	walk = func(id string, depth int, path string) {
		if inc != nil && !inc[id] {
			return
		}
		key := path + id
		kids := s.rdeps[id]
		re := seen[id]
		seen[id] = true
		rows = append(rows, row{kind: rowTask, id: id, depth: depth, key: key, hasKids: len(kids) > 0 && !re, revisit: re})
		if re || len(kids) == 0 || !m.expandedNow(key) {
			return
		}
		for _, k := range kids {
			walk(k, depth+1, key+"/")
		}
	}

	if len(chains) > 0 {
		rows = append(rows, row{kind: rowHeader, header: fmt.Sprintf("entrypoints — %d chain roots · children = dependents (what finishing unblocks)", len(chains))})
		for _, t := range chains {
			walk(t.ID, 0, "dag:")
		}
	}
	if len(singles) > 0 {
		rows = append(rows, row{kind: rowHeader, header: fmt.Sprintf("isolated — %d tasks with no dependency edges", len(singles))})
		for _, t := range singles {
			rows = append(rows, row{kind: rowTask, id: t.ID, depth: 0, key: "dag-iso:" + t.ID})
		}
	}
	return rows
}

// buildEpics renders the parent/child grouping tree.
func (m *tuiModel) buildEpics() []row {
	s := m.snap

	var inc map[string]bool
	if m.filterActive() {
		inc = map[string]bool{}
		for _, t := range s.tasks {
			if !m.matches(t) {
				continue
			}
			// Include the match and its parent chain (the render ancestors).
			for id := t.ID; id != ""; {
				if inc[id] {
					break
				}
				inc[id] = true
				p := s.byID[id].ParentID
				if s.byID[p] == nil {
					break
				}
				id = p
			}
		}
	}

	var rows []row
	var walk func(id string, depth int, path string)
	walk = func(id string, depth int, path string) {
		if inc != nil && !inc[id] {
			return
		}
		key := path + id
		kids := s.children[id]
		rows = append(rows, row{kind: rowTask, id: id, depth: depth, key: key, hasKids: len(kids) > 0})
		if len(kids) == 0 || !m.expandedNow(key) {
			return
		}
		for _, k := range kids {
			walk(k, depth+1, key+"/")
		}
	}
	for _, t := range s.tasks {
		// Dangling parents (deleted on another branch) demote the child to root
		// rather than hiding it.
		if t.ParentID == "" || s.byID[t.ParentID] == nil {
			walk(t.ID, 0, "epic:")
		}
	}
	return rows
}

// buildReady renders the dispatch queue: what `task list --ready` returns,
// in priority order. The status filter is moot here (ready ⇒ open), so only
// the search filter applies.
func (m *tuiModel) buildReady() []row {
	s := m.snap
	var rows []row
	for _, t := range s.tasks {
		if !s.ready[t.ID] || !m.searchMatches(t) {
			continue
		}
		rows = append(rows, row{kind: rowTask, id: t.ID, key: "ready:" + t.ID})
	}
	hdr := fmt.Sprintf("ready — %d dispatchable: open, unlocked, deps done, no children · enter = chain", len(rows))
	return append([]row{{kind: rowHeader, header: hdr}}, rows...)
}

// buildChain renders one task's full neighborhood: the transitive deps that
// gate it (upstream), the task itself, and everything it transitively
// unblocks (downstream). Filters deliberately do not apply — the view answers
// "what is the story of this one task".
func (m *tuiModel) buildChain() []row {
	s := m.snap
	if s.byID[m.chainID] == nil {
		return []row{{kind: rowHeader, header: "task no longer exists — esc to go back"}}
	}

	var rows []row
	walkEdges := func(start []string, edges map[string][]string, prefix string) {
		seen := map[string]bool{}
		var walk func(id string, depth int, path string)
		walk = func(id string, depth int, path string) {
			key := path + id
			kids := edges[id]
			re := seen[id]
			seen[id] = true
			rows = append(rows, row{kind: rowTask, id: id, depth: depth, key: key, hasKids: len(kids) > 0 && !re, revisit: re})
			if re || len(kids) == 0 || !m.expandedNow(key) {
				return
			}
			for _, k := range kids {
				walk(k, depth+1, key+"/")
			}
		}
		for _, id := range start {
			walk(id, 0, prefix)
		}
	}

	if up := s.deps[m.chainID]; len(up) > 0 {
		rows = append(rows, row{kind: rowHeader, header: fmt.Sprintf("▲ upstream — %d direct deps, what must finish first", len(up))})
		walkEdges(up, s.deps, "chain-up:")
	}
	rows = append(rows, row{kind: rowHeader, header: "● task"})
	rows = append(rows, row{kind: rowTask, id: m.chainID, key: "chain-self:" + m.chainID, focal: true})
	if dn := s.rdeps[m.chainID]; len(dn) > 0 {
		rows = append(rows, row{kind: rowHeader, header: fmt.Sprintf("▼ downstream — unblocks %d directly", len(dn))})
		walkEdges(dn, s.rdeps, "chain-dn:")
	}
	return rows
}
