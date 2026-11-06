"""
Readable picture of a provenance graph: one box per program, not per process.

The raw graph has a node for every exec, so a few minutes of normal use draws
hundreds of overlapping circles. An investigator's first question is "what ran
what, and how often", so this merges by program name:

    python main.py visualize
    python main.py visualize --graph graphs/tampered_binary_swap.gpickle

Each arrow's caller is the program that made the exec. When the graph builder
could not find that program's own start, for example VS Code launched before
the capture, the caller still comes from the event's `comm` field and is drawn
as "already running". The full graph stays in provenance.graphml.
"""
from __future__ import annotations

import json
import os
import pickle
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from core import config

OTHER = "other programs"

_COLOURS = {
    "user": ("#dbe9f6", "#2f6da8"),
    "root": ("#f9d9d4", "#b3301e"),
    "external": ("#eef0f2", "#6b7780"),
}
_ARROW, _ARROW_ROOT, _INK, _MUTED, _FLAG = "#6d7f8c", "#b3301e", "#16232c", "#51626e", "#d98a00"


def _program(attrs: dict[str, Any]) -> str:
    return os.path.basename(attrs.get("filename") or "") or "(unknown)"


def summarise(graph, max_programs: int = 24, flagged: set[str] | None = None,
              max_arrows: int = 30) -> dict[str, Any]:
    """Merge a provenance graph into programs and the calls between them."""
    flagged = flagged or set()
    starts: Counter = Counter()
    root_programs: set[str] = set()
    calls: dict[tuple[str, str], dict[str, Any]] = {}
    pairs: list[tuple[str, str, Any, bool]] = []
    flagged_programs: set[str] = set()

    for node, attrs in graph.nodes(data=True):
        if str(node) in flagged and not attrs.get("synthetic_root"):
            flagged_programs.add(_program(attrs))
        if attrs.get("type") != "process" or attrs.get("synthetic_root"):
            continue
        parent = next((source for source, _, edge in graph.in_edges(node, data=True)
                       if edge.get("relation") == "SPAWNS"
                       and not graph.nodes[source].get("synthetic_root")), None)
        caller = _program(graph.nodes[parent]) if parent is not None \
            else (attrs.get("comm") or "(unknown)")
        program = _program(attrs)
        is_root = attrs.get("uid") == 0
        starts[program] += 1
        if is_root:
            root_programs.add(program)
        pairs.append((caller, program, attrs.get("pid"), is_root))

    keep = {name for name, _ in starts.most_common(max_programs)}
    called_by = Counter(caller for caller, *_ in pairs)
    for name, _ in called_by.most_common(max_programs // 3):
        keep.add(name)
    # Root activity is what an investigator looks for: never fold it away.
    keep |= root_programs
    folded = {name for name in set(starts) | set(called_by) if name not in keep}
    rename = lambda name: OTHER if name in folded else name  # noqa: E731

    for caller, program, pid, is_root in pairs:
        key = (rename(caller), rename(program))
        call = calls.setdefault(key, {"events": 0, "pids": set(), "root": False})
        call["events"] += 1
        call["pids"].add(pid)
        call["root"] = call["root"] or is_root

    # Past this many arrows the picture is unreadable again. Root calls go
    # first, then the busiest, and the caption says how many were left out.
    ranked = sorted(calls, key=lambda key: (not calls[key]["root"], -calls[key]["events"], key))
    hidden = ranked[max_arrows:]
    calls = {key: calls[key] for key in ranked[:max_arrows]}

    merged: Counter = Counter()
    for name, count in starts.items():
        merged[rename(name)] += count
    programs = {name for pair in calls for name in pair}
    merged = Counter({name: count for name, count in merged.items() if name in programs})

    return {
        "programs": programs,
        "starts": merged,
        "calls": calls,
        "root": {rename(name) for name in root_programs},
        "external": {name for name in programs if name not in merged},
        "flagged": {rename(name) for name in flagged_programs},
        "folded": len(folded),
        "hidden_calls": len(hidden),
        "events": sum(starts.values()),
    }


def _layout(summary: dict[str, Any]) -> dict[str, tuple[int, float]]:
    """Left-to-right layers from callers to callees, with fewer crossings."""
    programs, calls = summary["programs"], summary["calls"]
    successors, predecessors = defaultdict(set), defaultdict(set)
    for caller, program in calls:
        if caller != program:
            successors[caller].add(program)
            predecessors[program].add(caller)

    layer: dict[str, int] = {}
    frontier = sorted(name for name in programs if not predecessors[name])
    remaining = set(programs)
    while remaining:
        if not frontier:   # only cycles are left: start from the busiest
            frontier = [max(sorted(remaining), key=lambda n: len(successors[n]))]
        following = []
        for name in frontier:
            if name in remaining:
                remaining.discard(name)
                layer[name] = max((layer[p] + 1 for p in predecessors[name] if p in layer),
                                  default=0)
                following.extend(sorted(successors[name]))
        frontier = following

    columns: dict[int, list[str]] = defaultdict(list)
    for name in sorted(programs, key=lambda n: (-summary["starts"][n], n)):
        columns[layer[name]].append(name)

    order = {name: float(i) for names in columns.values() for i, name in enumerate(names)}
    for _ in range(6):
        for column in sorted(columns):
            names = columns[column]
            def rank(name):
                near = list(predecessors[name] | successors[name])
                return sum(order[n] for n in near) / len(near) if near else order[name]
            names.sort(key=rank)
            for i, name in enumerate(names):
                order[name] = float(i)

    tallest = max(len(names) for names in columns.values())
    return {name: (column, (tallest - len(names)) / 2 + i)
            for column, names in columns.items() for i, name in enumerate(names)}


def _load_flagged(graph) -> set[str]:
    """Nodes the detector flagged, if its report describes this same graph."""
    path = Path(config.EVIDENCE_DIR) / "detection_report.json"
    if not path.exists():
        return set()
    report = json.loads(path.read_text(encoding="utf-8"))
    if (report.get("graph_nodes"), report.get("graph_edges")) != (
            graph.number_of_nodes(), graph.number_of_edges()):
        return set()
    return {item["node"] for item in report.get("detail", {}).get("top_suspicious_nodes", [])}


def draw(graph, output: str | Path, max_programs: int = 24) -> dict[str, Any]:
    """Render the summary to `output` and to an .svg beside it."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.lines import Line2D
    from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

    summary = summarise(graph, max_programs, _load_flagged(graph))
    if not summary["programs"]:
        raise SystemExit("the graph has no events to draw")
    positions = _layout(summary)

    columns = max(column for column, _ in positions.values()) + 1
    rows = max(row for _, row in positions.values()) + 1
    x_gap, y_gap, box_w, box_h = 3.9, 1.25, 2.15, 0.82
    figure, axes = plt.subplots(figsize=(max(9.0, columns * x_gap * 0.86 + 1.4),
                                         max(5.2, rows * y_gap * 0.86 + 2.5)), dpi=200)
    figure.patch.set_facecolor("white")
    axes.set_aspect("equal")
    axes.axis("off")

    centre = {name: (column * x_gap, -row * y_gap) for name, (column, row) in positions.items()}
    biggest = max(call["events"] for call in summary["calls"].values())
    labels = []

    # Fan arrows out along the box edge so several never share one point.
    outgoing, incoming = defaultdict(list), defaultdict(list)
    for caller, program in summary["calls"]:
        if caller != program:
            outgoing[caller].append(program)
            incoming[program].append(caller)
    for side in (outgoing, incoming):
        for name in side:
            side[name].sort(key=lambda other: -centre[other][1])

    def anchor(side, name, other):
        members = side[name]
        return ((members.index(other) + 1) / (len(members) + 1) - 0.5) * box_h * 0.8

    for (caller, program), call in summary["calls"].items():
        colour = _ARROW_ROOT if call["root"] else _ARROW
        width = 1.0 + 3.0 * (call["events"] / biggest) ** 0.5
        runs, tries = len(call["pids"]), call["events"]
        text = f"{runs} run{'s' if runs != 1 else ''}" + (f" · {tries} tries" if tries > runs else "")
        x1, y1 = centre[caller]
        x2, y2 = centre[program]

        if caller == program:
            axes.add_patch(FancyArrowPatch(
                (x1 + 0.45, y1 + box_h / 2), (x1 - 0.45, y1 + box_h / 2),
                connectionstyle="arc3,rad=1.1", arrowstyle="-|>", mutation_scale=12,
                color=colour, linewidth=width, zorder=1))
            labels.append((x1, y1 + box_h / 2 + 0.52, text, colour))
            continue

        forward = x2 > x1
        start = (x1 + box_w / 2 if forward else x1 - box_w / 2,
                 y1 - anchor(outgoing, caller, program))
        end = (x2 - box_w / 2 if forward else x2 + box_w / 2,
               y2 - anchor(incoming, program, caller))
        # Arcs clear the boxes between two distant columns; a same-column or
        # backward call bends away so it does not lie along a forward arrow.
        span = abs(positions[program][0] - positions[caller][0])
        bend = 0.0 if forward and span == 1 else (0.32 if forward else -0.38)
        axes.add_patch(FancyArrowPatch(
            start, end, connectionstyle=f"arc3,rad={bend}", arrowstyle="-|>",
            mutation_scale=13, color=colour, linewidth=width, shrinkA=1, shrinkB=2,
            alpha=0.9, zorder=1))
        fraction = 0.56
        labels.append((start[0] + (end[0] - start[0]) * fraction + (end[1] - start[1]) * bend * -0.5,
                       start[1] + (end[1] - start[1]) * fraction + (end[0] - start[0]) * bend * 0.5,
                       text, colour))

    for name, (x, y) in centre.items():
        kind = "root" if name in summary["root"] else \
            "external" if name in summary["external"] else "user"
        fill, edge = _COLOURS[kind]
        is_flagged = name in summary["flagged"]
        axes.add_patch(FancyBboxPatch(
            (x - box_w / 2, y - box_h / 2), box_w, box_h,
            boxstyle="round,pad=0,rounding_size=0.13", facecolor=fill,
            edgecolor=_FLAG if is_flagged else edge, linewidth=2.8 if is_flagged else 1.5,
            linestyle="--" if kind == "external" else "-", zorder=2))
        title = name if len(name) <= 19 else name[:18] + "…"
        count = summary["starts"][name]
        note = "already running" if kind == "external" else f"{count} exec{'s' if count != 1 else ''}"
        axes.text(x, y + 0.13, title, ha="center", va="center", fontsize=11.5,
                  fontweight="bold", color=_INK, zorder=3)
        axes.text(x, y - 0.2, note, ha="center", va="center", fontsize=8.5,
                  color=_MUTED, zorder=3)

    for x, y, text, colour in labels:
        axes.text(x, y, text, ha="center", va="center", fontsize=8, color=_INK, zorder=4,
                  bbox={"boxstyle": "round,pad=0.22", "facecolor": "white",
                        "edgecolor": "none", "alpha": 0.92})

    handles = [Line2D([], [], marker="s", linestyle="", markersize=11, markerfacecolor=fill,
                      markeredgecolor=edge, label=label)
               for present, (fill, edge), label in (
                   (True, _COLOURS["user"], "ran as a normal user"),
                   (bool(summary["root"]), _COLOURS["root"], "ran as root"),
                   (bool(summary["external"]), _COLOURS["external"],
                    "started before this capture"),
                   (bool(summary["flagged"]), ("white", _FLAG), "flagged by the GNN")) if present]
    figure.legend(handles=handles, loc="lower center", ncol=len(handles),
                  frameon=False, fontsize=9.5)

    axes.set_xlim(-box_w / 2 - 0.5, (columns - 1) * x_gap + box_w / 2 + 0.5)
    # room for arcs between distant columns, which curve past the boxes
    margin = 1.1 if columns > 2 and len(summary["calls"]) > columns * 2 else 0.5
    axes.set_ylim(-(rows - 1) * y_gap - box_h / 2 - margin, box_h / 2 + 0.6 + margin)
    subtitle = (f"{summary['events']} execs by {len(summary['programs'])} programs."
                " A run is one process. Tries include each PATH lookup.")
    if summary["folded"]:
        subtitle += f" {summary['folded']} rarer programs are grouped."
    if summary["hidden_calls"]:
        subtitle += f" {summary['hidden_calls']} rarer calls are not drawn."
    figure.suptitle("What ran what", fontsize=18, fontweight="bold", color=_INK, y=0.985)
    figure.text(0.5, 0.925, subtitle, ha="center", fontsize=10, color=_MUTED)
    figure.tight_layout(rect=(0, 0.06, 1, 0.91))

    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(output, facecolor="white")
    figure.savefig(output.with_suffix(".svg"), facecolor="white")
    plt.close(figure)
    return summary


def main(graph_path: str | None = None, output: str | None = None,
         max_programs: int = 24) -> Path:
    with open(graph_path or config.GRAPH_PICKLE, "rb") as handle:
        graph = pickle.load(handle)
    target = Path(output or f"{config.GRAPH_DIR}/provenance_graph.png")
    summary = draw(graph, target, max_programs)
    print(f"Picture : {target} (and {target.with_suffix('.svg').name})")
    print(f"Shows   : {summary['events']} execs by {len(summary['programs'])} programs")
    return target


if __name__ == "__main__":
    main()
