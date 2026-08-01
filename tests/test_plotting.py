import csv
import json

import matplotlib.figure
import pytest

import qcsd_lab.plotting as plotting
from qcsd_lab.capture import ObserverPacket
from qcsd_lab.plotting import (
    INCOMING,
    OUTGOING,
    calculate_metrics,
    plot_group,
)


def test_trace_comparison_uses_density_scatter_pairing_and_pdf_svg_outputs(tmp_path, monkeypatch):
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

    export_metadata = {kwargs["format"]: kwargs["metadata"] for _destination, kwargs in exports}
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
    legend_labels = {text.get_text() for text in figure.legends[0].get_texts()}
    assert "Outgoing controller actions" in legend_labels
    assert "Incoming controller actions" in legend_labels

    scatter = figure.axes[3]
    # Defense-independent plotting retains every packet. Every packet is one
    # hollow circular collection; no defense-specific threshold is applied.
    assert len(scatter.collections) == 3
    assert all(len(collection.get_facecolors()) == 0 for collection in scatter.collections)
    assert all(len(collection.get_paths()[0].vertices) > 8 for collection in scatter.collections)
    assert density.get_shared_x_axes().joined(density, scatter)
    assert density.patches  # The post-completion defence tail is shaded.
    assert density.get_xlim() == pytest.approx((0.0, 0.2))
    assert scatter.get_xlim() == pytest.approx((0.0, 0.2))
    assert not scatter.texts
    assert any("local time axis" in text.get_text() for text in figure.texts)
    assert any("actual direct-capture extent" in text.get_text() for text in figure.texts)
    assert any("receive-credit replacements" in text.get_text() for text in figure.texts)
    assert any("not logical target-cell counts" in text.get_text() for text in figure.texts)


def test_short_trace_uses_actual_extent_and_exact_tail_bounds(tmp_path, monkeypatch):
    sample = tmp_path / "walkie-talkie"
    _sample(sample, "walkie-talkie")
    run = json.loads((sample / "neqo/run.json").read_text(encoding="utf-8"))
    run["application_completion_monotonic_ns"] = 20_499_002
    (sample / "neqo/run.json").write_text(json.dumps(run), encoding="utf-8")
    trace_end_ns = 23_189_887
    monkeypatch.setattr(
        plotting,
        "sample_trace",
        lambda _sample_path: _observer_trace(duration_ns=trace_end_ns),
    )
    figures = []

    def capture(figure, destination, **kwargs):
        figures.append(figure)
        destination.write_text(kwargs.get("format", "pdf"), encoding="utf-8")

    monkeypatch.setattr(matplotlib.figure.Figure, "savefig", capture)
    plot_group(tmp_path)

    density, scatter = figures[0].axes
    expected_end = trace_end_ns / 1e9
    expected_completion = run["application_completion_monotonic_ns"] / 1e9
    assert density.get_xlim() == pytest.approx((0.0, expected_end))
    assert scatter.get_xlim() == pytest.approx((0.0, expected_end))
    assert len(density.patches) == 1
    assert len(scatter.patches) == 1
    for patch in (density.patches[0], scatter.patches[0]):
        assert patch.get_x() == pytest.approx(expected_completion)
        assert patch.get_width() == pytest.approx(expected_end - expected_completion)
    assert not scatter.texts


def test_seven_defenses_use_stable_order_and_common_axes_across_pages(
    tmp_path,
    monkeypatch,
):
    defenses = (
        "walkie-talkie",
        "front",
        "undefended",
        "wtf-pad",
        "traffic-morphing",
        "tamaraw",
        "static",
    )
    for defense in defenses:
        _sample(tmp_path / defense, defense)
    trace_by_defense = {
        defense: _observer_trace(
            duration_ns=(index + 1) * 100_000_000,
            maximum_frame_len=600 + index * 200,
        )
        for index, defense in enumerate(defenses)
    }
    monkeypatch.setattr(
        plotting,
        "sample_trace",
        lambda sample_path: trace_by_defense[sample_path.name],
    )
    figures = []

    def capture(figure, destination, **kwargs):
        figures.append(figure)
        destination.write_text(kwargs.get("format", "pdf"), encoding="utf-8")

    monkeypatch.setattr(matplotlib.figure.Figure, "savefig", capture)
    plot_group(tmp_path)
    assert (tmp_path / "trace-comparison.pdf").is_file()
    assert (tmp_path / "trace-comparison.svg").is_file()
    assert (tmp_path / "trace-comparison-2.pdf").is_file()
    assert (tmp_path / "trace-comparison-2.svg").is_file()
    pages = figures[::2]  # Each page is exported once as PDF and once as SVG.
    assert [len(figure.axes) for figure in pages] == [8, 6]
    assert [axis.get_title() for axis in pages[0].axes[:4]] == [
        "Undefended",
        "Static",
        "FRONT",
        "Tamaraw",
    ]
    assert [axis.get_title() for axis in pages[1].axes[:3]] == [
        "Traffic Morphing",
        "WTF-PAD",
        "Walkie-Talkie",
    ]
    density_limits = {
        axis.get_ylim() for figure in pages for axis in figure.axes[: len(figure.axes) // 2]
    }
    scatter_axes = [axis for figure in pages for axis in figure.axes[len(figure.axes) // 2 :]]
    assert len(density_limits) > 1  # Packet-density scales are panel-local.
    assert len({axis.get_xlim() for axis in scatter_axes}) == 7
    assert len({axis.get_ylim() for axis in scatter_axes}) == 1
    for figure in pages:
        columns = len(figure.axes) // 2
        for column in range(columns):
            density = figure.axes[column]
            scatter = figure.axes[columns + column]
            assert density.get_shared_x_axes().joined(density, scatter)
        if columns > 1:
            assert (
                not figure.axes[0]
                .get_shared_x_axes()
                .joined(
                    figure.axes[0],
                    figure.axes[1],
                )
            )


def test_schedule_action_kde_reuses_observed_bandwidth_and_cannot_expand_density_axis(
    tmp_path,
    monkeypatch,
):
    _sample(tmp_path / "undefended", "undefended")
    monkeypatch.setattr(plotting, "sample_trace", lambda _sample_path: _observer_trace())
    monkeypatch.setattr(
        plotting,
        "_schedule_action_times",
        lambda _sample, direction, _trace: (
            plotting.np.zeros(1_000) if direction == "outgoing" else plotting.np.asarray([])
        ),
    )
    calls = []
    original_density = plotting._density

    def record_density(values, grid, bandwidth=None):
        calls.append((len(values), bandwidth))
        return original_density(values, grid, bandwidth)

    monkeypatch.setattr(plotting, "_density", record_density)
    figures = []

    def capture(figure, destination, **kwargs):
        figures.append(figure)
        destination.write_text(kwargs.get("format", "pdf"), encoding="utf-8")

    monkeypatch.setattr(matplotlib.figure.Figure, "savefig", capture)
    plot_group(tmp_path)
    density_axis = figures[0].axes[0]
    observed_peaks = [
        max(line.get_ydata()) for line in density_axis.lines if line.get_linestyle() == "-"
    ]
    assert density_axis.get_ylim()[1] == pytest.approx(max(observed_peaks) * 1.05)
    assert len({bandwidth for _size, bandwidth in calls}) == 1


def test_schedule_action_times_include_every_incoming_credit_action(tmp_path):
    sample = tmp_path / "walkie-talkie"
    _sample(sample, "walkie-talkie")
    with (sample / "neqo/schedule.csv").open("a", newline="", encoding="utf-8") as output:
        csv.writer(output).writerow(
            [30_000, "incoming", 2, 0, 80_000, "credit_advertised", "", "", 2]
        )

        csv.writer(output).writerow(
            [40_000, "incoming", 2, 0, "", "missed", "", "missing_action", 3]
        )

    trace = _observer_trace()
    trace[0] = ObserverPacket(1_020_000_000, 0, "outgoing", 100, 100)
    actions = plotting._schedule_action_times(sample, "incoming", trace)

    # The second entry represents exact replacement credit, not another logical
    # mould cell. Both actual actions remain visible, while the terminal row
    # without an action timestamp is omitted rather than plotted at target time.
    assert actions.tolist() == pytest.approx([0.05, 0.06])


def test_schedule_action_times_require_clock_anchor(tmp_path):
    sample = tmp_path / "walkie-talkie"
    _sample(sample, "walkie-talkie")
    run = json.loads((sample / "neqo/run.json").read_text(encoding="utf-8"))
    del run["time_anchor_unix_ns"]
    (sample / "neqo/run.json").write_text(json.dumps(run), encoding="utf-8")

    assert (
        plotting._schedule_action_times(
            sample,
            "incoming",
            _observer_trace(),
        ).tolist()
        == []
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("id", "diagnostic"),
        ("capture_path", "captures/other.pcapng"),
        ("trace_path", "traces/other.csv"),
        ("length_basis", "udp.length"),
        ("capture_active_through_settle", False),
    ],
)
def test_classic_figure_rejects_noncanonical_observer_views(
    tmp_path,
    monkeypatch,
    field,
    value,
):
    sample = tmp_path / "undefended"
    _sample(sample, "undefended")
    metadata = json.loads((sample / "sample.json").read_text(encoding="utf-8"))
    metadata["views"][0][field] = value
    (sample / "sample.json").write_text(json.dumps(metadata), encoding="utf-8")
    monkeypatch.setattr(plotting, "sample_trace", lambda _sample_path: _observer_trace())

    with pytest.raises(ValueError, match="canonical direct-quic"):
        plot_group(tmp_path)


def test_svg_export_is_deterministic(tmp_path, monkeypatch):
    for defense in ("none", "front"):
        _sample(tmp_path / defense, defense)
    monkeypatch.setattr(plotting, "sample_trace", lambda _sample_path: _observer_trace())
    plot_group(tmp_path)
    first = (tmp_path / "trace-comparison.svg").read_bytes()
    plot_group(tmp_path)
    second = (tmp_path / "trace-comparison.svg").read_bytes()
    assert first == second


def test_complete_campaign_treats_required_plot_failure_as_fatal(tmp_path, monkeypatch):
    group = tmp_path / "monitored" / "visit"
    group.mkdir(parents=True)
    (group / "placeholder" / "sample.json").parent.mkdir()
    (group / "placeholder" / "sample.json").write_text("{}", encoding="utf-8")
    (tmp_path / "campaign.json").write_text(
        json.dumps(
            {
                "summary": {"passed": True},
                "configuration": {"defenses": []},
                "visits": [{"path": "monitored/visit"}],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        plotting,
        "plot_group",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("broken figure")),
    )
    with pytest.raises(ValueError, match="broken figure"):
        plotting.plot_run(tmp_path)

    receipt = json.loads((tmp_path / "campaign.json").read_text())
    receipt["summary"]["passed"] = False
    (tmp_path / "campaign.json").write_text(json.dumps(receipt), encoding="utf-8")
    assert plotting.plot_run(tmp_path) == []


def test_metrics_surface_padding_guard_as_operational_failure(tmp_path, monkeypatch):
    sample = tmp_path / "sample"
    neqo = sample / "neqo"
    traces = sample / "traces"
    traces.mkdir(parents=True)
    _runner_output(
        neqo,
        [100, 1200],
        diagnostics={
            "padding_events": 7,
            "padding_event_guard_triggered": True,
            "wtf_pad_incoming_shortfall_bytes": 1200,
        },
    )
    (traces / "primary.csv").write_text(
        "relative_time_ns,direction,length_bytes,signed_length_bytes\n"
        "0,outgoing,100,100\n"
        "1000000,incoming,1200,-1200\n",
        encoding="utf-8",
    )
    (sample / "sample.json").write_text(
        json.dumps(
            {
                "defense": "wtf-pad",
                "views": [
                    {
                        "id": "direct-quic",
                        "kind": "direct-quic",
                        "primary": True,
                        "valid": True,
                        "trace_path": "traces/primary.csv",
                        "length_basis": "frame.len",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(plotting, "sample_trace", lambda _sample_path: _observer_trace())
    metrics = calculate_metrics(sample)
    assert metrics["padding_events"] == 7
    assert metrics["padding_event_guard_triggered"] is True
    assert metrics["operationally_valid"] is False
    assert metrics["wire_bytes"] == 2500
    assert metrics["wire_bytes_outgoing"] == 1300
    assert metrics["wire_bytes_incoming"] == 1200
    assert metrics["wire_packets"] == 3
    assert metrics["trace_duration_seconds"] == pytest.approx(0.2)
    assert metrics["defense_tail_seconds"] == pytest.approx(0.17)
    assert metrics["defense_tail_bytes"] == 2400
    assert metrics["defense_tail_packets"] == 2
    assert metrics["fidelity_realization_errors"] == {
        "padding_event_guard_triggered": True,
        "wtf_pad_incoming_shortfall_bytes": 1200,
    }


def _sample(path, defense):
    path.mkdir()
    (path / "neqo").mkdir()
    (path / "sample.json").write_text(
        json.dumps(
            {
                "defense": defense,
                "state": "captured",
                "views": [
                    {
                        "id": "direct-quic",
                        "kind": "direct-quic",
                        "interface": "eth0",
                        "link_type": "Ethernet",
                        "length_basis": "frame.len",
                        "primary": True,
                        "valid": True,
                        "capture_active_through_settle": True,
                        "capture_path": "captures/direct-quic.pcapng",
                        "trace_path": "traces/direct-quic.csv",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (path / "neqo/run.json").write_text(
        json.dumps(
            {
                "time_anchor_unix_ns": 1_000_000_000,
                "defense_start_monotonic_ns": 50_000_000,
                "application_completion_monotonic_ns": 100_000_000,
                "responses": [],
            }
        ),
        encoding="utf-8",
    )
    with (path / "neqo/schedule.csv").open("w", newline="", encoding="utf-8") as destination:
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
        writer.writerow([20_000, "incoming", 1200, 0, 70_000, "credit_advertised", "", "", 1])
    with (path / "neqo/packets.csv").open("w", newline="", encoding="utf-8") as destination:
        writer = csv.writer(destination)
        writer.writerow(
            [
                "direction",
                "monotonic_us",
                "connection",
                "observed_udp_length",
                "scheduled_target",
                "satisfaction",
                "slot_id",
            ]
        )
        writer.writerow(["outgoing", 60_000, 0, 100, "", "unshaped", ""])
        writer.writerow(["outgoing", 70_000, 0, 1200, 1200, "satisfied", 0])
        writer.writerow(["incoming", 80_000, 0, 1200, "", "observed", ""])


def _runner_output(path, outgoing_sizes, *, diagnostics=None):
    path.mkdir(parents=True)
    diagnostics = diagnostics or {
        "padding_events": 0,
        "padding_event_guard_triggered": False,
    }
    (path / "run.json").write_text(
        json.dumps(
            {
                "completion_status": "complete",
                "defense_start_monotonic_ns": 10_000_000,
                "application_completion_monotonic_ns": 30_000_000,
                "responses": [{"bytes": 1000}],
                "defense_diagnostics": diagnostics,
            }
        ),
        encoding="utf-8",
    )
    with (path / "packets.csv").open("w", newline="", encoding="utf-8") as destination:
        writer = csv.writer(destination)
        writer.writerow(
            [
                "direction",
                "monotonic_us",
                "connection",
                "observed_udp_length",
                "scheduled_target",
                "satisfaction",
                "slot_id",
            ]
        )
        for index, size in enumerate(outgoing_sizes):
            writer.writerow(["outgoing", 10_000 + index * 1_000, 0, size, "", "unshaped", ""])
        writer.writerow(["incoming", 20_000, 0, 1200, "", "observed", ""])
    with (path / "schedule.csv").open("w", newline="", encoding="utf-8") as destination:
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
        writer.writerow([1_000, "outgoing", 1200, 0, 11_000, "satisfied", 1200, "", 0])
        writer.writerow([2_000, "incoming", 1200, 0, 12_000, "credit_advertised", "", "", 1])
    (path / "events.csv").write_text(
        "monotonic_us,connection,event,outcome,details\n",
        encoding="utf-8",
    )


def _observer_trace(
    *,
    duration_ns: int = 200_000_000,
    maximum_frame_len: int = 1200,
):
    return [
        ObserverPacket(1_000_000_000, 0, "outgoing", 100, 100),
        ObserverPacket(
            1_000_000_000 + duration_ns // 2,
            duration_ns // 2,
            "outgoing",
            maximum_frame_len,
            maximum_frame_len,
        ),
        ObserverPacket(
            1_000_000_000 + duration_ns,
            duration_ns,
            "incoming",
            maximum_frame_len,
            -maximum_frame_len,
        ),
    ]
