import csv
import json

import matplotlib.figure

import qcsd_lab.plotting as plotting
from qcsd_lab.capture import ObserverPacket
from qcsd_lab.plotting import INCOMING, OUTGOING, plot_group


def test_trace_comparison_uses_density_scatter_pairing_and_pdf_svg_outputs(
    tmp_path, monkeypatch
):
    for defense in ("none", "front", "tamaraw"):
        _sample(tmp_path / defense, defense)
    monkeypatch.setattr(plotting, "sample_trace", lambda _sample_path: _observer_trace())
    figures = []
    exports = []

    def capture(figure, destination, **kwargs):
        figures.append(figure)
        exports.append((destination, kwargs))
        if kwargs.get("format") == "svg":
            destination.write_bytes(b"<svg/>")
        else:
            destination.write_bytes(b"%PDF-1.7\n")

    monkeypatch.setattr(matplotlib.figure.Figure, "savefig", capture)
    output = plot_group(tmp_path)
    assert output == tmp_path / "trace-comparison.pdf"
    assert output.read_bytes().startswith(b"%PDF")
    assert (tmp_path / "trace-comparison.svg").exists()
    assert not list(tmp_path.glob("*.png"))
    assert not list(tmp_path.glob("*.html"))

    export_metadata = {
        kwargs["format"]: kwargs["metadata"] for _destination, kwargs in exports
    }
    assert export_metadata["pdf"]["CreationDate"] is None
    assert export_metadata["pdf"]["ModDate"] is None
    assert export_metadata["svg"]["Date"] is None

    figure = figures[0]
    assert len(figure.axes) == 6
    assert len(figure.legends) == 1
    density = figure.axes[0]
    line_styles = {(line.get_color(), line.get_linestyle()) for line in density.lines}
    assert (OUTGOING, "-") in line_styles
    assert (OUTGOING, "--") in line_styles
    assert (INCOMING, "-") in line_styles
    assert (INCOMING, "--") in line_styles
    assert any(line.get_linestyle() == ":" for line in density.lines)

    scatter = figure.axes[3]
    # Defense-independent plotting retains every packet. Every packet is one
    # hollow circular collection; no defense-specific threshold is applied.
    assert len(scatter.collections) == 3
    assert all(len(collection.get_facecolors()) == 0 for collection in scatter.collections)
    assert all(len(collection.get_paths()[0].vertices) > 8 for collection in scatter.collections)
    assert density.get_shared_x_axes().joined(density, scatter)


def test_svg_export_is_deterministic(tmp_path, monkeypatch):
    for defense in ("none", "front"):
        _sample(tmp_path / defense, defense)
    monkeypatch.setattr(plotting, "sample_trace", lambda _sample_path: _observer_trace())
    plot_group(tmp_path)
    first = (tmp_path / "trace-comparison.svg").read_bytes()
    plot_group(tmp_path)
    second = (tmp_path / "trace-comparison.svg").read_bytes()
    assert first == second


def _sample(path, defense):
    path.mkdir()
    (path / "neqo").mkdir()
    (path / "sample.json").write_text(
        json.dumps({"defense": defense, "state": "captured"}),
        encoding="utf-8",
    )
    (path / "neqo/run.json").write_text(
        json.dumps(
            {
                "time_anchor_unix_ns": 1_000_000_000,
                "defense_start_monotonic_ns": 50_000_000,
                "application_completion_monotonic_ns": 250_000_000,
                "responses": [],
            }
        ),
        encoding="utf-8",
    )
    with (path / "neqo/schedule.csv").open(
        "w", newline="", encoding="utf-8"
    ) as destination:
        writer = csv.writer(destination)
        writer.writerow(
            [
                "target_time_us",
                "direction",
                "size",
                "connection",
                "action_time_us",
                "satisfaction",
                "observed_size",
                "miss_reason",
                "slot_id",
            ]
        )
        writer.writerow([10_000, "outgoing", 1200, 0, 60_000, "satisfied", 1200, "", 0])
        writer.writerow(
            [20_000, "incoming", 1200, 0, 70_000, "credit_advertised", "", "", 1]
        )


def _observer_trace():
    return [
        ObserverPacket(1_000_000_000, 0, "outgoing", 100, 100, 0),
        ObserverPacket(1_100_000_000, 100_000_000, "outgoing", 1200, 1200, 0),
        ObserverPacket(1_200_000_000, 200_000_000, "incoming", 1200, -1200, 0),
    ]
