import csv
import json

import matplotlib.figure
import pytest

import qcsd_lab.plotting as plotting
from qcsd_lab.capture import ObserverPacket


def test_trace_comparison_preserves_density_scatter_actions_completion_and_tail(
    tmp_path,
    monkeypatch,
):
    samples = []
    traces = {}
    for defense in ("undefended", "front", "tamaraw"):
        sample = _sample(tmp_path / defense)
        samples.append((defense, sample))
        traces[sample] = _trace()
    figures = []

    def capture(figure, destination, **kwargs):
        figures.append(figure)
        destination.write_text("<svg/>", encoding="utf-8")
        assert kwargs["format"] == "svg"
        assert kwargs["metadata"]["Date"] is None

    monkeypatch.setattr(matplotlib.figure.Figure, "savefig", capture)
    outputs = plotting.plot_trace_comparison(samples, tmp_path / "comparison", traces=traces)

    assert outputs == [tmp_path / "comparison.svg"]
    assert not list(tmp_path.glob("*.pdf"))
    figure = figures[0]
    assert len(figure.axes) == 6
    assert len(figure.legends) == 1
    density = figure.axes[0]
    styles = {(line.get_color(), line.get_linestyle()) for line in density.lines}
    assert (plotting.OUTGOING, "-") in styles
    assert (plotting.OUTGOING, "--") in styles
    assert (plotting.INCOMING, "-") in styles
    assert (plotting.INCOMING, "--") in styles
    assert (plotting.COMPLETION, ":") in styles
    packet_axis = figure.axes[3]
    signed_y = [
        offset[1] for collection in packet_axis.collections for offset in collection.get_offsets()
    ]
    assert any(value > 0 for value in signed_y)
    assert any(value < 0 for value in signed_y)
    assert density.patches  # Shaded defence tail.
    assert "local time axis" in figure.texts[-1].get_text()


def test_seven_modes_are_ordered_and_split_into_four_column_svg_pages(tmp_path, monkeypatch):
    defenses = [
        "walkie-talkie",
        "front",
        "undefended",
        "wtf-pad",
        "static",
        "traffic-morphing",
        "tamaraw",
    ]
    samples = []
    traces = {}
    for index, defense in enumerate(defenses):
        sample = _sample(tmp_path / defense)
        samples.append((defense, sample))
        traces[sample] = _trace(duration_ns=(index + 1) * 100_000_000, frame_len=600 + index)
    figures = []

    def capture(figure, destination, **_kwargs):
        figures.append(figure)
        destination.write_text("<svg/>", encoding="utf-8")

    monkeypatch.setattr(matplotlib.figure.Figure, "savefig", capture)
    outputs = plotting.plot_trace_comparison(samples, tmp_path / "comparison", traces=traces)

    assert [path.name for path in outputs] == ["comparison.svg", "comparison-2.svg"]
    assert [len(figure.axes) for figure in figures] == [8, 6]
    assert [axis.get_title() for axis in figures[0].axes[:4]] == [
        "Undefended",
        "Static",
        "FRONT",
        "Tamaraw",
    ]
    assert [axis.get_title() for axis in figures[1].axes[:3]] == [
        "Traffic Morphing",
        "WTF-PAD",
        "Walkie-Talkie",
    ]
    scatter_axes = [axis for figure in figures for axis in figure.axes[len(figure.axes) // 2 :]]
    assert len({axis.get_ylim() for axis in scatter_axes}) == 1
    assert len({axis.get_xlim() for axis in scatter_axes}) == 7


def test_svg_trace_export_is_byte_deterministic(tmp_path):
    samples = []
    traces = {}
    for defense in ("undefended", "front"):
        sample = _sample(tmp_path / defense)
        samples.append((defense, sample))
        traces[sample] = _trace()
    destination = tmp_path / "comparison"

    plotting.plot_trace_comparison(samples, destination, traces=traces)
    first = destination.with_suffix(".svg").read_bytes()
    plotting.plot_trace_comparison(samples, destination, traces=traces)

    assert destination.with_suffix(".svg").read_bytes() == first


def test_trace_comparison_rejects_single_or_empty_samples(tmp_path):
    sample = _sample(tmp_path / "undefended")
    with pytest.raises(ValueError, match="at least two"):
        plotting.plot_trace_comparison(
            [("undefended", sample)],
            tmp_path / "comparison",
            traces={sample: _trace()},
        )
    second = _sample(tmp_path / "front")
    with pytest.raises(ValueError, match="empty"):
        plotting.plot_trace_comparison(
            [("undefended", sample), ("front", second)],
            tmp_path / "comparison",
            traces={sample: _trace(), second: []},
        )


def test_schedule_actions_include_replacement_credit_and_omit_terminal_miss(tmp_path):
    sample = _sample(tmp_path / "walkie-talkie")
    with (sample / "neqo/schedule.csv").open("a", newline="", encoding="utf-8") as output:
        writer = csv.writer(output)
        writer.writerow([80_000, "incoming", 120, "satisfied", 120, ""])
        writer.writerow(["", "incoming", 120, "missed", "", "missing_action"])

    assert plotting._schedule_action_times(sample, "incoming", _trace()).tolist() == pytest.approx(
        [0.07, 0.08]
    )


def test_schedule_actions_require_clock_anchor(tmp_path):
    sample = _sample(tmp_path / "front")
    run = json.loads((sample / "neqo/run.json").read_text(encoding="utf-8"))
    del run["time_anchor_unix_ns"]
    (sample / "neqo/run.json").write_text(json.dumps(run), encoding="utf-8")

    assert plotting._schedule_action_times(sample, "outgoing", _trace()).tolist() == []


def test_metrics_come_only_from_authoritative_capture_and_neqo_files(tmp_path):
    sample = _sample(tmp_path / "wtf-pad", guard=True)
    metrics = plotting.calculate_metrics(sample, "wtf-pad", trace=_trace())

    assert metrics["wire_bytes"] == 440
    assert metrics["wire_bytes_outgoing"] == 320
    assert metrics["wire_bytes_incoming"] == 120
    assert metrics["wire_packets"] == 3
    assert metrics["application_completion_seconds"] == pytest.approx(0.2)
    assert metrics["trace_duration_seconds"] == pytest.approx(0.3)
    assert metrics["defense_tail_seconds"] == pytest.approx(0.1)
    assert metrics["padding_event_guard_triggered"] is True
    assert metrics["operationally_valid"] is False
    assert metrics["fidelity_realization_errors"] == {
        "padding_event_guard_triggered": True,
        "wtf_pad_incoming_shortfall_bytes": 1200,
    }
    assert metrics["primary_observer"] == "direct-quic"
    assert metrics["primary_length_basis"] == "frame.len"


def test_aggregate_figures_are_svg_only_and_deterministic(tmp_path):
    records = [
        {
            "defense": "undefended",
            "application_completion_seconds": 0.2,
            "wire_byte_overhead_ratio": 0.0,
        },
        {
            "defense": "front",
            "application_completion_seconds": 0.4,
            "wire_byte_overhead_ratio": 1.5,
        },
    ]
    latency = plotting.plot_aggregate_latency(records, tmp_path / "latency.svg")
    overhead = plotting.plot_aggregate_overhead(records, tmp_path / "overhead.svg")
    before = {path.name: path.read_bytes() for path in (latency, overhead)}

    plotting.plot_aggregate_latency(records, latency)
    plotting.plot_aggregate_overhead(records, overhead)

    assert {path.name: path.read_bytes() for path in (latency, overhead)} == before
    assert not list(tmp_path.glob("*.pdf"))


def test_custom_variants_of_one_runtime_defense_remain_distinct_treatments(tmp_path, monkeypatch):
    records = [
        {
            "defense": "traffic-morphing",
            "defense_variant": "tm-a",
            "application_completion_seconds": 0.3,
        },
        {
            "defense": "traffic-morphing",
            "defense_variant": "tm-b",
            "application_completion_seconds": 0.8,
        },
    ]
    labels, medians = plotting._ordered_series(records, "application_completion_seconds")
    assert labels == ["Traffic Morphing (tm-a)", "Traffic Morphing (tm-b)"]
    assert medians == [0.3, 0.8]

    samples = []
    traces = {}
    variants = {}
    for variant in ("tm-a", "tm-b"):
        sample = _sample(tmp_path / variant)
        samples.append(("traffic-morphing", sample))
        traces[sample] = _trace()
        variants[sample] = variant
    figures = []

    def capture(figure, destination, **_kwargs):
        figures.append(figure)
        destination.write_text("<svg/>", encoding="utf-8")

    monkeypatch.setattr(matplotlib.figure.Figure, "savefig", capture)
    plotting.plot_trace_comparison(
        samples,
        tmp_path / "variants",
        traces=traces,
        variants=variants,
    )
    assert [axis.get_title() for axis in figures[0].axes[:2]] == labels


def _sample(path, guard=False):
    neqo = path / "neqo"
    neqo.mkdir(parents=True)
    diagnostics = {}
    if guard:
        diagnostics = {
            "padding_events": 10,
            "padding_event_guard_triggered": True,
            "wtf_pad_incoming_shortfall_bytes": 1200,
        }
    (neqo / "run.json").write_text(
        json.dumps(
            {
                "time_anchor_unix_ns": 1_000_000_000,
                "application_completion_monotonic_ns": 200_000_000,
                "responses": [{"bytes": 500}],
                "defense_diagnostics": diagnostics,
            }
        ),
        encoding="utf-8",
    )
    (neqo / "packets.csv").write_text(
        "observed_udp_length\n100\n120\n",
        encoding="utf-8",
    )
    (neqo / "events.csv").write_text("connection,details\n", encoding="utf-8")
    (neqo / "schedule.csv").write_text(
        "action_time_us,direction,size,satisfaction,observed_size,miss_reason\n"
        "50000,outgoing,100,satisfied,100,\n"
        "70000,incoming,120,satisfied,120,\n",
        encoding="utf-8",
    )
    (path / "capture.pcapng").write_bytes(b"capture")
    return path


def _trace(duration_ns=300_000_000, frame_len=100):
    return [
        ObserverPacket(1_000_000_000, 0, "outgoing", frame_len, frame_len, frame_len - 8),
        ObserverPacket(1_100_000_000, 100_000_000, "incoming", 120, -120, 112),
        ObserverPacket(
            1_000_000_000 + duration_ns,
            duration_ns,
            "outgoing",
            220,
            220,
            212,
        ),
    ]
