// SPDX-License-Identifier: Apache-2.0
package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/reflow/truncate"
	"github.com/muesli/reflow/wordwrap"
)

var (
	styDim     = lipgloss.NewStyle().Faint(true)
	styHeader  = lipgloss.NewStyle().Faint(true).Italic(true)
	styOpen    = lipgloss.NewStyle()
	styReady   = lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Bold(true)
	styInProg  = lipgloss.NewStyle().Foreground(lipgloss.Color("3"))
	styDone    = lipgloss.NewStyle().Foreground(lipgloss.Color("2")).Faint(true)
	styDropped = lipgloss.NewStyle().Foreground(lipgloss.Color("8")).Faint(true).Strikethrough(true)
	styBlocked = lipgloss.NewStyle().Foreground(lipgloss.Color("1"))
	styBadge   = lipgloss.NewStyle().Foreground(lipgloss.Color("6")).Faint(true)
	styLock    = lipgloss.NewStyle().Foreground(lipgloss.Color("5"))
	styFocal   = lipgloss.NewStyle().Bold(true).Underline(true)
	stySection = lipgloss.NewStyle().Foreground(lipgloss.Color("4")).Bold(true)
	styFlash   = lipgloss.NewStyle().Foreground(lipgloss.Color("3")).Bold(true)

	stySelected = lipgloss.NewStyle().
			Background(lipgloss.AdaptiveColor{Light: "254", Dark: "237"}).
			Bold(true)
	styTabActive = lipgloss.NewStyle().
			Background(lipgloss.AdaptiveColor{Light: "254", Dark: "237"}).
			Bold(true)
)

// statusGlyph returns the one-cell marker for a task and its style. Ready
// tasks (dispatchable now) override the plain open glyph.
func statusGlyph(s *snapshot, t *Task) (string, lipgloss.Style) {
	if s.ready[t.ID] {
		return "▶", styReady
	}
	switch t.Status {
	case StatusInProgress:
		return "◐", styInProg
	case StatusDone:
		return "●", styDone
	case StatusDropped:
		return "⊘", styDropped
	case StatusBlocked:
		return "✕", styBlocked
	default:
		return "○", styOpen
	}
}

func shortID(id string) string {
	if len(id) > 10 {
		return id[:10]
	}
	return id
}

func fmtTime(t time.Time) string {
	return t.Local().Format("2006-01-02 15:04")
}

// padTo right-pads a styled string with spaces to the given display width.
func padTo(s string, w int) string {
	if gap := w - lipgloss.Width(s); gap > 0 {
		return s + strings.Repeat(" ", gap)
	}
	return s
}

func truncTo(s string, w int) string {
	if w < 1 {
		return ""
	}
	return truncate.StringWithTail(s, uint(w), "…")
}

func (m *tuiModel) View() string {
	if m.width == 0 || m.height == 0 {
		return "loading…"
	}
	var body string
	if m.showHelp {
		body = m.renderHelp()
	} else {
		body = m.renderBody()
	}
	return m.renderHeader() + "\n" + body + "\n" + m.renderFooter()
}

func (m *tuiModel) renderHeader() string {
	tabs := []string{styDim.Render(" taskdb ")}
	for _, t := range []struct {
		key  string
		mode viewMode
		name string
	}{{"1", viewDAG, "DAG"}, {"2", viewEpics, "Epics"}, {"3", viewReady, "Ready"}} {
		label := fmt.Sprintf(" %s %s ", t.key, t.name)
		if m.mode == t.mode {
			tabs = append(tabs, styTabActive.Render(label))
		} else {
			tabs = append(tabs, styDim.Render(label))
		}
	}
	if m.mode == viewChain {
		tabs = append(tabs, styTabActive.Render(fmt.Sprintf(" chain %s ", shortID(m.chainID))))
	}
	left := strings.Join(tabs, "")

	s := m.snap
	right := fmt.Sprintf("▶%d ready · ○%d ◐%d ✕%d ●%d ⊘%d · %d tasks ",
		len(s.ready), s.counts[StatusOpen], s.counts[StatusInProgress],
		s.counts[StatusBlocked], s.counts[StatusDone], s.counts[StatusDropped], len(s.tasks))
	line1 := left
	if gap := m.width - lipgloss.Width(left) - lipgloss.Width(right); gap > 0 {
		line1 += strings.Repeat(" ", gap) + styDim.Render(right)
	}
	return line1 + "\n" + styDim.Render(strings.Repeat("─", max(0, m.width)))
}

func (m *tuiModel) renderFooter() string {
	var state []string
	if m.flash != "" {
		state = append(state, styFlash.Render(m.flash))
	}
	if m.searching {
		state = append(state, "find: "+m.search+"▌  (enter keep · esc clear)")
	} else if m.search != "" {
		state = append(state, fmt.Sprintf("find: %q", m.search))
	}
	if m.statusFilter != "" {
		f := fmt.Sprintf("status: %s", m.statusFilter)
		if m.mode == viewReady {
			f += " (no effect on Ready)"
		}
		state = append(state, f)
	}
	if len(state) > 0 && !m.searching && (m.search != "" || m.statusFilter != "") {
		state = append(state, "esc clears")
	}

	hints := "j/k move · h/l fold · H/L fold all · c chain · / find · s status · tab view · r reload · ? help · q quit"
	line2 := truncTo(strings.Join(state, " · "), m.width)
	if len(state) == 0 {
		line2 = styDim.Render(truncTo(hints, m.width))
	}
	return styDim.Render(strings.Repeat("─", max(0, m.width))) + "\n" + line2
}

func (m *tuiModel) renderBody() string {
	bodyH := m.bodyHeight()
	listW := m.width
	detailW := 0
	// The detail pane appears once there is room for both panes; below that
	// the chain view + detail-free list still work.
	if m.width >= 100 {
		detailW = min(max(2*m.width/5, 42), 72)
		listW = m.width - detailW - 3 // " │ " separator
	}

	left := m.renderListLines(listW, bodyH)
	if detailW == 0 {
		return strings.Join(left, "\n")
	}
	right := m.renderDetailLines(detailW, bodyH)
	sep := styDim.Render(" │ ")
	var b strings.Builder
	for i := range bodyH {
		b.WriteString(padTo(left[i], listW))
		b.WriteString(sep)
		b.WriteString(right[i])
		if i < bodyH-1 {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// renderListLines renders exactly h lines of the left pane.
func (m *tuiModel) renderListLines(w, h int) []string {
	lines := make([]string, 0, h)
	if len(m.rows) == 0 {
		msg := "no tasks"
		if m.filterActive() {
			msg = "nothing matches — esc clears filters"
		}
		lines = append(lines, styDim.Render(msg))
	}
	for i := m.offset; i < len(m.rows) && len(lines) < h; i++ {
		lines = append(lines, m.renderRow(m.rows[i], i == m.cursor, w))
	}
	for len(lines) < h {
		lines = append(lines, "")
	}
	return lines
}

func (m *tuiModel) renderRow(r row, selected bool, w int) string {
	if r.kind == rowHeader {
		return styHeader.Render(truncTo("── "+r.header+" ──", w))
	}
	t := m.snap.byID[r.id]
	if t == nil {
		return ""
	}

	fold := "  "
	if r.hasKids {
		if m.expandedNow(r.key) {
			fold = "▾ "
		} else {
			fold = "▸ "
		}
	}
	glyph, gst := statusGlyph(m.snap, t)
	indent := strings.Repeat("  ", r.depth)

	var badges []string
	if t.Priority > 0 {
		badges = append(badges, fmt.Sprintf("p%d", t.Priority))
	}
	if m.mode == viewEpics {
		if prog := m.snap.progress[t.ID]; prog[1] > 0 {
			badges = append(badges, fmt.Sprintf("%d/%d", prog[0], prog[1]))
		}
	}
	if len(m.snap.notes[t.ID]) > 0 {
		badges = append(badges, fmt.Sprintf("✎%d", len(m.snap.notes[t.ID])))
	}
	lock := ""
	if t.LockedBy != "" {
		lock = " [lock]"
	}
	revisit := ""
	if r.revisit {
		revisit = " ⤴"
	}
	badge := ""
	if len(badges) > 0 {
		badge = " " + strings.Join(badges, " ")
	}

	prefix := indent + fold + glyph + " "
	avail := w - lipgloss.Width(prefix) - lipgloss.Width(badge) - lipgloss.Width(lock) - lipgloss.Width(revisit)
	title := truncTo(t.Title, max(avail, 6))

	if selected {
		// One flat style for the whole line: per-segment colors carry their own
		// resets, which would cut the highlight background mid-line.
		return stySelected.Render(padTo(prefix+title+badge+lock+revisit, w))
	}

	titleSty := lipgloss.NewStyle()
	switch {
	case r.focal:
		titleSty = styFocal
	case r.revisit:
		titleSty = styDim
	case t.Status == StatusDone:
		titleSty = styDone
	case t.Status == StatusDropped:
		titleSty = styDropped
	}
	return styDim.Render(indent+fold) + gst.Render(glyph) + " " +
		titleSty.Render(title) + styBadge.Render(badge) + styLock.Render(lock) + styDim.Render(revisit)
}

// renderDetailLines renders exactly h lines of the right pane for the
// selected task, honoring detailScroll.
func (m *tuiModel) renderDetailLines(w, h int) []string {
	var lines []string
	sel, ok := m.selectedRow()
	if !ok {
		lines = []string{styDim.Render("no selection")}
	} else {
		lines = m.detailContent(m.snap.byID[sel.id], w)
	}

	scroll := min(m.detailScroll, max(0, len(lines)-h))
	end := min(scroll+h, len(lines))
	out := make([]string, 0, h)
	out = append(out, lines[scroll:end]...)
	if end < len(lines) {
		out[len(out)-1] = styDim.Render(fmt.Sprintf("… %d more lines · J/K scroll", len(lines)-end+1))
	}
	for len(out) < h {
		out = append(out, "")
	}
	return out
}

func (m *tuiModel) detailContent(t *Task, w int) []string {
	if t == nil {
		return []string{styDim.Render("no selection")}
	}
	s := m.snap
	var lines []string
	add := func(l string) { lines = append(lines, truncTo(l, w)) }
	field := func(name, val string) { add(styDim.Render(fmt.Sprintf("%-8s ", name)) + val) }

	glyph, gst := statusGlyph(s, t)
	add(styFocal.Render(truncTo(t.Title, w)))
	add("")
	field("id", t.ID)
	status := gst.Render(glyph) + " " + string(t.Status)
	if s.ready[t.ID] {
		status += styReady.Render("  · ready now")
	}
	field("status", status)
	field("priority", fmt.Sprintf("p%d", t.Priority))
	if p := s.byID[t.ParentID]; p != nil {
		field("epic", styDim.Render(shortID(p.ID))+" "+p.Title)
	}
	if t.Branch != "" {
		field("branch", t.Branch)
	}
	if t.LockedBy != "" {
		field("lock", styLock.Render(fmt.Sprintf("%s · since %s", t.LockedBy, fmtTime(msToTime(t.LockedAt)))))
	}
	field("created", fmtTime(t.CreatedAt)+styDim.Render(" · updated ")+fmtTime(t.UpdatedAt))

	related := func(title string, ids []string) {
		if len(ids) == 0 {
			return
		}
		add("")
		add(stySection.Render(fmt.Sprintf("%s (%d)", title, len(ids))))
		for _, id := range ids {
			rt := s.byID[id]
			g, gs := statusGlyph(s, rt)
			add("  " + gs.Render(g) + " " + styDim.Render(shortID(id)) + " " + truncTo(rt.Title, w-16))
		}
	}
	related("depends on", s.deps[t.ID])
	related("blocks", s.rdeps[t.ID])
	related("children", s.children[t.ID])

	if t.Body != "" {
		add("")
		add(stySection.Render("body"))
		for _, l := range strings.Split(wordwrap.String(t.Body, w-2), "\n") {
			lines = append(lines, "  "+l)
		}
	}

	if notes := s.notes[t.ID]; len(notes) > 0 {
		add("")
		add(stySection.Render(fmt.Sprintf("notes (%d)", len(notes))))
		for _, n := range notes {
			author := n.Author
			if author == "" {
				author = "anon"
			}
			add(styDim.Render(fmt.Sprintf("  ── %s · %s", author, fmtTime(n.CreatedAt))))
			for _, l := range strings.Split(wordwrap.String(n.Body, w-2), "\n") {
				lines = append(lines, "  "+l)
			}
		}
	}
	return lines
}

func (m *tuiModel) renderHelp() string {
	help := []string{
		stySection.Render("taskdb tui — explore the task graph"),
		"",
		stySection.Render("views"),
		"  1  DAG     dependency chains: roots have no deps; children are dependents",
		"  2  Epics   parent/child grouping · done/total per epic",
		"  3  Ready   the dispatch queue: open, unlocked, deps done, no children",
		"  c  Chain   upstream deps + downstream dependents of the selected task",
		"  tab next view · esc back / clear filters",
		"",
		stySection.Render("move"),
		"  j/k ↑/↓    move            g/G  top/bottom",
		"  ctrl+d/u   half page       J/K  scroll the detail pane",
		"",
		stySection.Render("fold"),
		"  l/→/enter  expand          h/←  collapse, or jump to parent",
		"  space      toggle          L/H  expand/collapse all",
		"",
		stySection.Render("filter"),
		"  /          title/ID filter (matches keep their ancestors visible)",
		"  s          cycle status: all → open → in-progress → blocked → done → dropped",
		"",
		stySection.Render("glyphs"),
		"  ▶ ready  ○ open  ◐ in-progress  ✕ blocked  ● done  ⊘ dropped  ⤴ shown above  ✎ notes",
		"",
		styDim.Render("  r reload from the live DB · q quit · any key closes help"),
	}
	bodyH := m.bodyHeight()
	out := make([]string, 0, bodyH)
	for i := 0; i < bodyH && i < len(help); i++ {
		out = append(out, "  "+truncTo(help[i], m.width-2))
	}
	for len(out) < bodyH {
		out = append(out, "")
	}
	return strings.Join(out, "\n")
}
