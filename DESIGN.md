---
name: SentinelNet
description: Precision Telemetry — Slate Navy and Indigo modern enterprise network intelligence dashboard with fluid responsive adaptability.
colors:
  slate-base: "#0b0f17"
  slate-surface: "#121a24"
  slate-recess: "#16202d"
  slate-relief: "#1d2a3b"
  slate-border: "#233245"
  slate-border-strong: "#324760"
  cta-primary: "#3b82f6"
  cta-press: "#2563eb"
  text: "#f1f5f9"
  text-muted: "#94a3b8"
  text-soft: "#64748b"
  lamp-energised: "#10b981"
  lamp-caution: "#f59e0b"
  lamp-fault: "#ef4444"
  lamp-idle: "#64748b"
  on-lamp: "#ffffff"
  conductor-a: "#3b82f6"
  conductor-b: "#f59e0b"
  conductor-c: "#10b981"
  conductor-d: "#a855f7"
  conductor-trace: "#f43f5e"
  severity-critical: "#f87171"
  severity-high: "#fb923c"
  severity-medium: "#facc15"
  severity-low: "#34d399"
typography:
  legend-hero:
    fontFamily: "Saira Condensed, Arial Narrow, Helvetica Neue, sans-serif"
    fontSize: "25px"
    fontWeight: 600
    lineHeight: 1.15
    letterSpacing: "0.02em"
  legend-title:
    fontFamily: "Saira Condensed, Arial Narrow, sans-serif"
    fontSize: "17px"
    fontWeight: 600
    lineHeight: 1.2
    letterSpacing: "0.02em"
  plate-header:
    fontFamily: "Saira Condensed, Arial Narrow, sans-serif"
    fontSize: "12px"
    fontWeight: 600
    lineHeight: 1.2
    letterSpacing: "0.14em"
  micro-tag:
    fontFamily: "Saira Condensed, Arial Narrow, sans-serif"
    fontSize: "9px"
    fontWeight: 600
    lineHeight: 1.4
    letterSpacing: "0.1em"
  pill-label:
    fontFamily: "Saira Condensed, Arial Narrow, sans-serif"
    fontSize: "11px"
    fontWeight: 600
    lineHeight: 1.4
    letterSpacing: "0.1em"
  legend-sub:
    fontFamily: "Saira Condensed, Arial Narrow, sans-serif"
    fontSize: "15px"
    fontWeight: 600
    lineHeight: 1.2
    letterSpacing: "0.02em"
  plate-title:
    fontFamily: "Saira Condensed, Arial Narrow, sans-serif"
    fontSize: "21px"
    fontWeight: 600
    lineHeight: 1.2
    letterSpacing: "0.06em"
  plate-label:
    fontFamily: "Saira Condensed, Arial Narrow, sans-serif"
    fontSize: "10px"
    fontWeight: 600
    lineHeight: 1.4
    letterSpacing: "0.16em"
  control-cap:
    fontFamily: "Saira Condensed, Arial Narrow, sans-serif"
    fontSize: "13px"
    fontWeight: 600
    lineHeight: 1.25
    letterSpacing: "0.1em"
  prose:
    fontFamily: "-apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Helvetica, Arial, sans-serif"
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.55
    letterSpacing: "0"
  reading:
    fontFamily: "Azeret Mono, ui-monospace, Cascadia Mono, Consolas, monospace"
    fontSize: "30px"
    fontWeight: 500
    lineHeight: 1.05
    letterSpacing: "-0.02em"
  data:
    fontFamily: "Azeret Mono, ui-monospace, Cascadia Mono, Consolas, monospace"
    fontSize: "12.5px"
    fontWeight: 400
    lineHeight: 1.5
    letterSpacing: "0"
rounded:
  square: "0"
  edge: "2px"
  plate: "8px"
  lens: "50%"
  pill: "999px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "12px"
  lg: "14px"
  xl: "18px"
  xxl: "24px"
  isolation: "18px"
components:
  control:
    backgroundColor: "{colors.relief}"
    textColor: "{colors.ink}"
    typography: "{typography.control-cap}"
    rounded: "{rounded.edge}"
    padding: "9px 14px"
    width: "100%"
  control-primary:
    backgroundColor: "{colors.ink}"
    textColor: "{colors.plate}"
    typography: "{typography.control-cap}"
    rounded: "{rounded.edge}"
    padding: "9px 14px"
  control-secondary:
    textColor: "{colors.ink}"
    typography: "{typography.control-cap}"
    rounded: "{rounded.edge}"
    padding: "9px 14px"
  control-destructive:
    textColor: "{colors.lamp-fault}"
    typography: "{typography.control-cap}"
    rounded: "{rounded.edge}"
    padding: "9px 14px"
  field:
    backgroundColor: "{colors.recess}"
    textColor: "{colors.ink}"
    typography: "{typography.data}"
    rounded: "{rounded.square}"
    padding: "8px 10px 8px 30px"
    width: "100%"
  bay-panel:
    backgroundColor: "{colors.plate}"
    textColor: "{colors.ink}"
    rounded: "{rounded.square}"
    padding: "16px 18px 18px"
  plate-header-strip:
    backgroundColor: "{colors.relief}"
    textColor: "{colors.ink-muted}"
    typography: "{typography.plate-header}"
    padding: "8px 18px"
  instrument:
    backgroundColor: "{colors.plate}"
    textColor: "{colors.ink}"
    typography: "{typography.reading}"
    rounded: "{rounded.square}"
    padding: "12px 14px"
  schedule-header:
    backgroundColor: "{colors.relief}"
    textColor: "{colors.ink-muted}"
    typography: "{typography.plate-label}"
    padding: "9px 14px"
  schedule-cell:
    backgroundColor: "{colors.recess}"
    textColor: "{colors.ink}"
    typography: "{typography.data}"
    padding: "9px 14px"
  bay-index-item:
    textColor: "{colors.ink-muted}"
    typography: "{typography.control-cap}"
    rounded: "{rounded.square}"
    padding: "9px 16px 9px 15px"
    width: "100%"
  bay-index-item-active:
    backgroundColor: "{colors.relief}"
    textColor: "{colors.ink}"
  lamp:
    rounded: "{rounded.lens}"
    size: "11px"
  status-energised:
    backgroundColor: "rgba(47, 149, 78, 0.14)"
    textColor: "#1e6b3c"
    typography: "{typography.plate-label}"
    rounded: "{rounded.square}"
    padding: "4px 8px"
  status-caution:
    backgroundColor: "rgba(184, 121, 26, 0.15)"
    textColor: "#8a5a0f"
    typography: "{typography.plate-label}"
    rounded: "{rounded.square}"
    padding: "4px 8px"
  status-fault:
    backgroundColor: "rgba(192, 57, 43, 0.13)"
    textColor: "#9d2b20"
    typography: "{typography.plate-label}"
    rounded: "{rounded.square}"
    padding: "4px 8px"
  engraved-tag:
    backgroundColor: "{colors.relief}"
    textColor: "{colors.ink-muted}"
    typography: "{typography.plate-label}"
    rounded: "{rounded.square}"
    padding: "2px 7px"
  title-block:
    backgroundColor: "{colors.relief}"
    textColor: "{colors.ink-muted}"
    typography: "{typography.plate-label}"
    padding: "8px 16px"
---

# Design System: SentinelNet

## Overview

**Creative North Star: "The Mimic Panel"**

Every substation has a wall that *is* the network: a mimic board, where the bus
bars are engraved into laminate, each bay hangs off the bus in the same place it
occupies in the yard, and an isolator's state is legible from across the control
room because its *shape* changes, not just its colour. When those boards moved to
screens they became the SCADA one-line, and the notation survived the move
intact. SentinelNet is drawn as that board. The estate is a one-line diagram
indexed by bay; the tables are cable schedules; the panels are engraved plates;
and the thing that tells you something is wrong is a lamp, not a chart.

The system exists in two renditions, and neither is the default. The light
rendition is the physical board: a cool grey-green laminate plate, black
engraved lettering, grooves catching a highlight along their top edge. The dark
rendition is its SCADA successor: slate, not black, because a control screen is
never off. They are not a colour inversion of each other — the engraving
direction flips, the grain coarsens and fades, the lamps shift to screen
luminance. Both are real artifacts of the same tradition, and the interface
picks up whichever the operating system asks for until someone says otherwise.

The load-bearing rule is that **colour means state and nothing else**. There is
no accent colour in this system. Hierarchy is made of engraving depth, ink
weight, letterspacing and space; emphasis is the highest-contrast ink block on
the plate. That constraint is what buys the lamps their power: when the only
coloured things on a screen are the four indicator states and the conductors of
a diagram, a single amber lens is impossible to miss from across a room. It also
means the board still works for an operator who cannot distinguish those hues —
every state carries a distinct geometry as well.

**Key Characteristics:**

- Two authored renditions of one drawing, never a theme toggle
- Colour is state; hierarchy is engraving, weight and space
- Square corners everywhere; the only curve in the system is a lamp lens
- State is carried by symbol geometry first and colour second
- Legend capitals for structure, monospace for every measured value
- A plate grain, not a 1px bevel, carries the material

## Colors

Two grounds, one ink family, four lamps, four conductors, and a separate CVSS
ramp. Nothing else has permission to be coloured.

### Primary

The two grounds are the primary colour decision, and they are surfaces rather
than accents — each owns its whole rendition.

- **Laminate** (#d4d7cf) and **Plate** (#e6e7e1): the light rendition's page and
  its panels. Cool grey-green, the colour of engraving stock — deliberately not
  cream, which is where this kind of interface usually lands.
- **Console** (#12171b) and **Bay** (#1e242a): the dark rendition. Slate with a
  blue cast rather than near-black; a control screen at rest still glows
  slightly, and a true black ground would make the lamps look like neon.
- **Panels are darker than the page in the dark rendition and lighter than it in
  the light one.** Both directions read as *recessed into* the board, which is
  what a bay actually is.

### Secondary — the lamps

Four states, each with a geometry as well as a hue, so the board survives
greyscale, distance, and colour blindness.

- **Energised** (#2f8f4e light / #56c07a dark): filled lens, filled isolator.
- **Caution** (#b8791a / #e0a03c): half-filled isolator — the diagonal split
  stays visible with all colour removed.
- **Fault** (#c0392b / #ef6b5e): hollow isolator, solid outline.
- **Unpolled** (#7d848b / #6c7a83): hollow isolator, *dashed* outline. This is
  the state of a device that has never been interrogated, and it is deliberately
  not fault — a fresh estate is not a broken one.

### Tertiary — the conductors

- **Conductor A–D** (#1f6fb2 · #b8791a · #2e8b57 · #6b4423): the phase-colour
  code, used only for distinguishing lines and series in a diagram — the
  protocol breakdown, the one-line's runs. Never for interface chrome.
- **Trace** (#7b3fb5): reserved for the active path being traced across a
  diagram. It overprints everything, the way a course line does on a map.

### Neutral

- **Ink** (#16191c) / **Ink Muted** (#4a5058) / **Ink Soft** (#525860) on the
  light rendition; **Ink Inverse** (#e8ebe6) / (#a2acb2) / (#909ba2) on the dark.
  Three steps, no more. Every pair against every surface it is used on clears
  4.5:1 — including soft ink on the raised table-header surface, which is the
  tightest pair in the system at 4.51:1.
- **Score** (#a8ada4) and **Score Deep** (#8b9188): the engraved groove and the
  heavier score that separates bay groups. Their dark counterparts are #333d44
  and #46535c.
- **Engrave Hi / Lo**: the highlight and shadow of the groove itself
  (`rgba(255,255,255,0.85)` over `rgba(30,36,32,0.28)` on laminate; 0.07 over
  0.45 on slate). Flipping these two values is most of what makes the two
  renditions feel like different materials rather than inverted colours.

### Ink on a lamp

**On Lamp** (#ffffff on laminate, #12171b on slate). Text almost never sits on a
state colour — it sits on a plate, next to a lamp. The exception is a control
that *is* the state while you are pressing it: the destructive button's hover,
where the fault lamp becomes the fill. That one case needs an ink that inverts
with the rendition; a fixed white reads 5.44:1 on the laminate fault but 3.03:1
on the slate one, because the dark rendition's lamps are lighter, not darker.
Never use this token on a wash — a wash sits over a plate, so the `-ink` lamp
variants apply there.

### CVSS ramp (vulnerability triage only)

**Critical** (#a3231a) · **High** (#985806) · **Medium** (#6f6410) · **Low**
(#2c6b3f), each on a tinted wash with a matching hairline. Re-inked per
rendition. This ramp maps to a published score and appears in exactly one place.

### Topology palettes (map surfaces only)

The topology map is drawn onto a canvas by vis-network, which cannot resolve
`var(--…)`. Colours there are read from the active rendition at draw time with
`cssVar()` — that is why literals appear in `static/js/topology.js` as
*fallbacks*, never as the value itself. Three populations live there, and only
the first is part of this system:

- **State** — always the lamp ramp via `cssVar('--lamp-*-ink')`. Same four
  states, same meaning, same geometry rule as everywhere else.
- **Device-type and VTP-domain ramps** — categorical encodings, not state. A
  category has no severity, so it may not borrow the lamp ramp; these are
  independent hues chosen for separability at small sizes on both grounds. They
  colour icons, borders and pills, never body text.
- **The minimal map rendition** — a deliberate third rendition, neither laminate
  nor slate: a white-ground engineering drawing with pastel node fills and dark
  ink, for printing a topology and reading it on paper. It is fixed by intent;
  it does not follow the theme, and it must not be "corrected" to tokens.

### Named Rules

**The Colour Is State Rule.** Colour carries state and diagram identity. It is
never emphasis, never brand, never decoration. A heading icon tinted amber
regardless of what the heading says is the exact violation this rule exists to
catch. If something needs to stand out and is not a state, give it ink weight,
size, or space.

**The Geometry First Rule.** Every state must be distinguishable with all colour
removed. A new state needs a new shape before it is allowed a new hue, and the
legend must draw that shape by reusing the real component, never a hand-styled
copy of it.

**The Unpolled Is Not Fault Rule.** Never-interrogated and unreachable are
different facts and must never share a symbol. Absence of data is its own state.

## Typography

**Legend Font:** Saira Condensed (fallback Arial Narrow, Helvetica Neue)
**Prose Font:** the platform UI stack (-apple-system, Segoe UI, Roboto)
**Data Font:** Azeret Mono (fallback ui-monospace, Cascadia Mono, Consolas)

**Character:** Saira Condensed is the engraved legend plate — condensed,
mechanical, built for uppercase at small sizes with wide tracking, which is
exactly how a panel is labelled. Azeret Mono is squarish and slightly severe,
closer to a plotter or an event printer than to a code editor. Prose is left to
the platform on purpose: it is the smallest part of this interface, and spending
a third webfont on it would buy nothing. **All faces are self-hosted from
`static/fonts/` (86 KB, latin subset) — never a CDN.** An isolated management
LAN is a confirmed deployment, and a legend that silently falls back to the
platform condensed sans there would take the system's whole voice with it.

### Hierarchy

- **Legend Hero** (Saira Condensed 600, 25px, +0.02em): the tab title in the
  title block. One per view.
- **Legend Title** (600, 17px): panel and section headings.
- **Plate Header** (600, 12px, uppercase, +0.14em): the engraved strip across the
  top of a bay panel.
- **Plate Title** (600, 21px): the login title.
  Modal headers do NOT use it — `.modal-header h3` shares the Plate Header
  step with `.panel > h3:first-child`, because a modal header is the same
  engraved strip across the top of a bay.
- **Legend Sub** (600, 15px): sub-section headings inside a bay.
- **Pill Label** (600, 11px, uppercase, +0.1em): status pills, the title-block
  cartouche, the one-line legend. The most repeated small step in the system.
- **Plate Label** (600, 10px, uppercase, +0.16em): field labels, table headers,
  tags, nav group headings (+0.18em).
- **Micro Tag** (600, 9px, uppercase, +0.1em): role pills and inline config chips,
  where a tag must not out-weigh the value beside it.
- **Control Cap** (600, 13px, uppercase, +0.1em): every button and nav item.
- **Prose** (platform stack, 400, 14px/1.55): explanatory copy, capped at 66ch.
- **Reading** (Azeret Mono 500, 30px, -0.02em): an instrument's value.
- **Data** (Azeret Mono 400, 12.5px): every table cell, every measured value,
  every time stamp — set with `tabular-nums` so columns align.

### Named Rules

**The Measured Value Rule.** Anything an engineer compares against another
number — counts, ports, VLANs, byte totals, timestamps, meter readings — is set
in the data face with tabular figures. Prose numbers stay in prose.

**The Uppercase Ceiling Rule.** Uppercase belongs to 13px and below, where wide
tracking makes it an engraved legend. Titles are never uppercased; at 17px and
up the condensed face is already doing the work.

## Layout

A two-column grid: `318px 1fr`, 14px gutter, 14px page padding. The sidebar
width is a custom property (`--sidebar-w`) so the collapsed rail can rewrite it
to 62px and the main column reflows from the grid definition alone. Only
`grid-template-columns` transitions, never `all`.

The sidebar is the **bay index**: sticky, independently scrolling, its scrollbar
thumb invisible at rest and appearing on hover or focus-within so the board's
edge stays clean. Groups are separated by a scored rule under an uppercase
heading. The active item is *pressed into* the laminate — a relief background,
an inverted groove, and a 3px ink spine that survives the collapsed rail, where
labels drop to `font-size: 0` (never `display: none`, so they stay available to
screen readers and to the RBAC gate that is the only thing allowed to hide a nav
item).

Content follows one spine: **title block → one-line → schedules**. The title
block carries the heading, one sentence of prose, and the single primary control.
The drawing sits on a reticle background — a 24px measuring grid, present only
where something is actually measured.

**Spacing rhythm:** a 2px base with a 4/8/12/14/18/24 structure. One value is
semantic rather than rhythmic: **18px of isolation to the left of every
destructive control**, a deliberate gap so a fault-coloured button is never
adjacent to the thing you meant to press. It collapses to a top margin on narrow
screens rather than disappearing.

**Breakpoints:** 1700px (reading widths clamp to 1560px; tables never clamp),
1200px (hero and instrument rows go single-column), 1100px, 1001px (rail
available above), 1000px (sidebar unsticks and stacks; bays wrap to two per
row), 900px (chat shell stacks), 620px (single column, controls go full width,
schedule padding tightens).

### Named Rules

**The Tables Don't Clamp Rule.** Reading widths are capped; data widths are not.
A firewall policy has twelve columns and needs every pixel an ultrawide offers.

**The Isolation Gap Rule.** A destructive control keeps 18px of empty space
between it and its neighbours, and stays outlined until deliberately focused.
Borrowed from the panel discipline it is named after, where the consequence of a
mis-press is measured in outages.

## Elevation & Depth

Depth is **engraved, not stacked**. Every surface carries a 1px highlight along
its top inner edge and a 1px shadow along its bottom — the cross-section of a
groove cut into laminate. Because those two values swap intensity between
renditions, the same rule reads as a groove in a plate under room light and as a
seam on a screen. The active nav item inverts the groove, which is precisely
what a pressed panel switch does.

Over that sits the **plate grain**: an feTurbulence fractal-noise data-URI tiled
at 140px, applied as a background *layer* on every panel, card, aside and modal.
Its opacity is baked into the SVG once (0.13 on laminate, 0.09 on slate — the
screen's granularity is finer and fainter than a plate's grain) rather than
multiplied by a second opacity on a wrapper, which is how a grain ends up
mathematically present and visually absent. It is a background layer specifically
so it introduces no stacking context: a `z-index: -1` pseudo-element would have
forced `isolation: isolate` onto nine selectors and trapped every dropdown and
modal inside them.

Real shadows are reserved for the four things that genuinely leave the board:
the login card, modals, the background-job monitor, and map overlays.

### Shadow Vocabulary

- **Float** (`0 18px 40px -12px rgba(22,25,28,0.42)` light; `0 20px 44px -12px
  rgba(0,0,0,0.72)` dark): modals and the login card.
- **Lift** (`0 8px 22px -10px` / `0 10px 26px -12px`): map legend and tooltips.
- **Groove** (`inset 0 1px 0 <engrave-hi>, inset 0 -1px 0 <engrave-lo>`): every
  resting surface. Not decoration — it is the material.
- **Pressed** (`inset 0 1px 3px <engrave-lo>`): active controls, selected chips,
  the active nav item.
- **Lamp** (`0 0 0 1px <state wash>, 0 1px 4px -1px <state>`): indicator lenses.

### Named Rules

**The Engraved Depth Rule.** Depth comes from a groove and a tone step. If two
surfaces do not read as separate, the tone step is wrong — adding a drop shadow
is not the fix.

**The Grain Must Read Rule.** A material that computes to two levels out of 255
is a token, not a material. Attenuate the grain in exactly one place so its
strength stays legible and adjustable.

## Shapes

Square where the edge is a cut: `border-radius: 0` on every table, field and
tag, 2px on controls, as the smallest possible chamfer on a machined edge.

Panels, cards and modals carry a single 8px token, `--card-border-radius` —
one value, in one place, which the three selectable theme variants raise to
12-14px. It is the only rounded step in the base palette, and adding a second
one is the drift this rule exists to catch.

The other curves in the system are the **lamp lens** (a perfect circle) and the
**status pill** (999px) — both curved because the object they depict is.
The isolator is a 13px square rotated 45°, which is the IEC symbol.

Borders are uniformly 1px. There is no 2px variant and no dashed stroke except
where dashing *is* the meaning — the unpolled isolator. Interactive elements
change border *colour*, never weight, so nothing shifts by a pixel on hover.

The recurring silhouette beyond the rectangle is the **bay**: a dropper falling
from the bus, an isolator on the dropper, and a labelled node beneath it.

### Named Rules

**The One Curve Rule.** If it is round, it is a lamp or it depicts one. Rounding
a container is how this system stops looking like itself.

## Components

### Controls

- **Shape:** 2px chamfer, full width by default (they were designed for the
  sidebar column); `width: auto` inside a sub-tab bar.
- **Primary:** solid ink block — the highest contrast available on the plate.
  One per view. In the light rendition that is near-black on laminate; in the
  dark it is near-white on slate. It is never a colour.
- **Secondary:** transparent with a scored border, filling to relief on hover.
- **Destructive:** outlined in fault, filling only on hover or deliberate focus,
  and separated by the isolation gap.
- **Disabled:** recessed surface, soft ink, no hover response.
- **Icon control:** 28px square, scored border, ink on hover.

### Fields

Recessed surface, scored border, pressed inner shadow, data face at 13px. Focus
takes a 2px ink outline inset by 1px plus an ink border — no glow, because a
glow on a plate is not a thing that happens. Labels are plate labels above the
field. **Checkboxes and radios are excluded from the width and padding rules by
explicit `:not()` selectors**, pinned by a regression test.

### Schedules (tables)

Relief header in plate labels, sticky to the top. Cells in the data face at
12.5px with scored bottom rules. Hover fills the row to relief. A row with
unsaved edits takes a caution wash and a 1px caution border-left; a disabled row
drops to 55% opacity with a neutral rule. Wrapped in a scored container that
scrolls on its own.

### Lamps and status pills

An 11px lens with a 1.5px bezel ring and a state halo, paired with an uppercase
legend. The pill variant sets the lamp on a wash of its own state with a
matching hairline. Four states, four geometries — see Colors.

### Bay index (navigation)

See Layout. Group headings are scored; items are control caps; the active item is
pressed with an ink spine.

### One-line diagram (signature component)

The estate drawn as a single-line: a 3px ink bus with end-caps, a dropper per
bay, a rotated-square isolator carrying state, and a labelled node holding the
bay's reading. Bays are **tenants**, ordered by size, with the tail aggregated
into one summary bay so the bus never overflows. Below the drawing sits the
**legend** — the symbol contract — built from the real bay components so a
geometry change propagates to it automatically. Below that, the **title block**:
fleet totals in a cartouche strip, where a technical drawing has always put its
quantities.

### Event strip (signature component)

The control-room printer: one row per event, most recent first, a monospace time
column, the event text, and a status pill. It has an empty state, and when the
viewer lacks the privilege to read it the section stays on the page and says so
rather than vanishing.

### Instruments

A plate label over a 30px monospace reading. Used for a measurement that has its
own scale; the meter variant adds a scored track with a state-coloured fill and a
right-aligned numeral of fixed width so a column of readings aligns.

## Do's and Don'ts

### Do:

- **Do** carry every state in a distinct geometry first, then colour.
- **Do** make the primary action the ink block — one per view.
- **Do** set every measured value in Azeret Mono with tabular figures.
- **Do** keep both renditions authored: any new token needs a light value and a
  dark value, and neither may be derived by inverting the other.
- **Do** self-host any new face in `static/fonts/` and reference it via
  `@font-face`. The exe bundles `static/` wholesale, so it ships automatically.
- **Do** resolve tokens through `cssVar()` before handing a colour to a canvas
  library (vis.js, xterm.js) — those cannot parse `var()`.
- **Do** give a destructive control its 18px of isolation.
- **Do** say why a section is empty or withheld, rather than removing it.
- **Do** add both an `it` and an `en` entry to `static/js/i18n.js` for every new
  string.

### Don't:

- **Don't** introduce an accent colour. There isn't one, and adding one dissolves
  the rule that makes the lamps legible.
- **Don't** round a container. Square is the form language; 2px on controls is
  the entire allowance.
- **Don't** add a drop shadow to a resting surface — fix the tone step instead.
- **Don't** animate `width`, `height`, `padding` or `margin`.
- **Don't** use the CVSS ramp for anything that is not a CVSS rating.
- **Don't** let a `background:` shorthand overwrite a surface — use
  `background-color`, or the plate grain is silently erased.
- **Don't** create a stacking context (`isolation`, `z-index` on a wrapper,
  `transform` on an ancestor) around content that contains dropdowns or modals.
- **Don't** load a font, icon or library from a CDN without a local fallback:
  isolated management LANs are a confirmed deployment.
- **Don't** hide a first-viewport element behind a role gate without leaving an
  explanation in its place.
