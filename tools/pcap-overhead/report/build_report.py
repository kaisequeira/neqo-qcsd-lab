#!/usr/bin/env python3
"""Create a review-only study report from completed final-PCAP analysis.

No packet captures, timing receipts, execution logs or classifications are
read.  The input tables must have been generated from the same verified
120,000-session manifest and metrics snapshot.  This tool does not publish.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import statistics
from pathlib import Path

MODES = ("undefended", "front", "tamaraw", "buflo", "cs-buflo", "wtf-pad")
DEFENSES = MODES[1:]
METRICS = ("ip_bytes", "observed_span")
FINAL_MANIFEST_SHA256 = "ef0e87f1138db2675e655813b0667b3860235df5c635f045e18f48fac1d72abf"
LABELS = {"undefended": "Undefended", "front": "FRONT", "tamaraw": "Tamaraw",
          "buflo": "BuFLO", "cs-buflo": "CS-BuFLO", "wtf-pad": "WTF-PAD"}
NOTES = {
    "front": "https://drive.google.com/file/d/1CbTNUWej19Wd5jxJBDq_1JkPqODrv93o/view",
    "tamaraw": "https://drive.google.com/file/d/1OS_Jj5o8iC2BJ711JdXWyz-RaerWOBsB/view",
    "buflo": "https://drive.google.com/file/d/1AlhLDnhTctkMZN5wvyyuogjVxeOJDT-E/view",
    "cs-buflo": "https://drive.google.com/file/d/1RGMQuIpTmC0fLrAuU6atIz_YYNLoOTnl/view",
    "wtf-pad": "https://drive.google.com/file/d/1zqQLj_giQPe1_vVArHFuTMvCJSnnB-Zy/view",
}
PRACTICALITY = {
    "front": "The original design aims to add cover without deliberately delaying real packets. These observed spans cannot establish that the live implementation had zero user delay; padding volume, contention and lifecycle behavior must also be considered.",
    "tamaraw": "Fixed-direction pacing and stopping rules can alter both packet volume and the visible padding tail. Interpret observed cost alongside the implemented schedules and avoid treating the mode name as proof of paper-equivalent behavior.",
    "buflo": "Dated study records describe enqueue deadlines, scheduling failures and relaxed configurations during live capture. Those cases illustrate implementation difficulty but are not a final-cohort failure rate; the final MAL cohort's outgoing-window variants should not be silently pooled when discussing configuration.",
    "cs-buflo": "Adaptive pacing, chaff availability and HTTP/3 stream progress are practical implementation considerations. A completed packet capture alone cannot show that the intended schedule or cover behavior was fully realized.",
    "wtf-pad": "The documented exploratory model used scaled timing histograms; available records do not establish that every final session used the same model. Low observed cost alone would not establish a representative fit, faithful behavior or privacy effectiveness.",
}


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def read_csv(path):
    with Path(path).open(newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def num(value, name):
    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("Missing or invalid numeric field: " + name) from exc
    if not math.isfinite(result):
        raise ValueError("Non-finite numeric field: " + name)
    return result


def integer(value, name):
    n = num(value, name)
    if not n.is_integer() or n < 0:
        raise ValueError("Invalid nonnegative integer: " + name)
    return int(n)


def valid_hash(value, name):
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("Missing or invalid SHA-256: " + name)
    return value


def keyed(rows, names):
    out = {}
    for row in rows:
        key = tuple(row.get(k, "") for k in names)
        if not all(key) or key in out:
            raise ValueError("Missing or duplicate table key: " + repr(key))
        out[key] = row
    return out


def close(a, b, name):
    if not math.isclose(a, b, rel_tol=1e-9, abs_tol=1e-8):
        raise ValueError("Inconsistent table value: " + name)


def percentile(values, percent):
    """The aggregate uses NumPy's default linear/R7 percentile."""
    values = sorted(values)
    position = (len(values) - 1) * percent / 100
    lo, hi = math.floor(position), math.ceil(position)
    return values[lo] + (values[hi] - values[lo]) * (position - lo)


def pct(x):
    return f"{x:+,.2f}%"


def amount(x, metric):
    return f"{x:,.2f} bytes" if metric == "ip_bytes" else f"{x:,.4f} s"


def ci(row, stem):
    lo = num(row[stem + "_low"], stem + "_low")
    hi = num(row[stem + "_high"], stem + "_high")
    if lo > hi:
        raise ValueError("Inverted confidence interval")
    return f"[{pct(lo)}, {pct(hi)}]"


def inspect(aggregate, descriptive, figures, *, manifest, expected_manifest_sha=FINAL_MANIFEST_SHA256,
            expected_domains=50, sessions=400):
    """Validate full-census status, joins and numerical cross-consistency."""
    aggregate, descriptive, figures = map(Path, (aggregate, descriptive, figures))
    quality = json.loads((aggregate / "quality.json").read_text(encoding="utf-8"))
    desc = json.loads((descriptive / "descriptive-provenance.json").read_text(encoding="utf-8"))
    fig = json.loads((figures / "figure-provenance.json").read_text(encoding="utf-8"))
    expected = len(MODES) * expected_domains * sessions
    mh = valid_hash(quality.get("manifest_sha256"), "manifest")
    if mh != expected_manifest_sha or sha(manifest) != mh:
        raise ValueError("Input manifest does not match the pinned final handoff and completed analysis")
    snapshot = valid_hash(quality.get("metric_rows_content_sha256"), "metric rows")
    ah = valid_hash(quality.get("analysis_script_sha256"), "aggregate code")
    valid_hash(desc.get("descriptive_code_sha256"), "descriptive code")
    valid_hash(fig.get("script_sha256"), "figure code")
    if (not isinstance(quality.get("identity_or_other_flags"), dict)
            or quality.get("status") != "complete" or quality.get("manifest_sessions") != expected
            or quality.get("accepted_metric_rows") != expected or quality.get("extractor_errors") != 0
            or quality.get("identity_or_other_flags")):
        raise ValueError("A complete, error-free, identity-verified capture census is required")
    quality_by_condition = quality.get("quality_by_condition")
    if not isinstance(quality_by_condition, dict) or set(quality_by_condition) != set(MODES):
        raise ValueError("Condition-level quality report is missing")
    for mode in MODES:
        row = quality_by_condition[mode]
        if (not isinstance(row, dict) or row.get("rows") != expected_domains * sessions
                or any(not isinstance(row.get(k), int) or isinstance(row.get(k), bool) or row[k] < 0
                       for k in ("ip_valid_false", "ip_valid_missing", "strict_timestamp_order_not_true",
                                 "truncated_packets", "direction_complete"))):
            raise ValueError("Invalid condition-level quality report: " + mode)
        if (row["ip_valid_false"] + row["ip_valid_missing"] > row["rows"]
                or row["strict_timestamp_order_not_true"] > row["rows"]
                or row["direction_complete"] > row["rows"]):
            raise ValueError("Condition-level capture count exceeds total: " + mode)
    if (desc.get("status") != "complete" or desc.get("manifest_sha256") != mh
            or desc.get("metric_rows_content_sha256") != snapshot or desc.get("aggregate_code_sha256") != ah
            or desc.get("metric_rows") != expected):
        raise ValueError("Descriptive results are not tied to this completed metrics snapshot")
    if (fig.get("status") != "complete" or fig.get("manifest_sha256") != mh
            or fig.get("metric_rows_content_sha256") != snapshot
            or fig.get("accepted_metric_rows") != expected or fig.get("manifest_sessions") != expected):
        raise ValueError("Figure provenance is not tied to this completed metrics snapshot")
    for name in ("quality.json", "overall-overheads.csv", "domain-overheads.csv"):
        if fig.get("inputs_sha256", {}).get(name) != sha(aggregate / name):
            raise ValueError("Figure input hash mismatch: " + name)
    for name in ("01-overall-overheads.svg", "01-overall-overheads.pdf",
                 "02-domain-spread.svg", "02-domain-spread.pdf"):
        if not (figures / name).is_file() or (figures / name).stat().st_size == 0:
            raise ValueError("Missing or empty final figure: " + name)

    summaries = keyed((r for r in read_csv(aggregate / "overall-overheads.csv")
                       if r.get("metric") in METRICS), ("defense", "metric"))
    details = keyed((r for r in read_csv(aggregate / "domain-overheads.csv")
                     if r.get("metric") in METRICS), ("defense", "metric", "domain"))
    distributions = keyed(read_csv(descriptive / "session-distributions-by-condition.csv"),
                          ("defense", "metric"))
    cohorts = keyed(read_csv(descriptive / "session-distributions-by-cohort.csv"),
                    ("defense", "domain", "metric"))
    offsets = keyed(read_csv(descriptive / "capture-epoch-offsets-by-domain.csv"),
                    ("defense", "domain"))
    shared = keyed(read_csv(descriptive / "shared-utc-day-summary.csv"), ("defense", "metric"))
    sensitivities = keyed(read_csv(descriptive / "sensitivity-overall.csv"), ("defense", "metric"))

    if set(summaries) != {(d, m) for d in DEFENSES for m in METRICS}:
        raise ValueError("Missing or unexpected primary comparison")
    if set(distributions) != {(d, m) for d in MODES for m in METRICS}:
        raise ValueError("Missing or unexpected condition distributions")
    if set(shared) != set(summaries) or set(sensitivities) != set(summaries):
        raise ValueError("Missing or unexpected sensitivity summaries")
    domains = {k[2] for k in details}
    if len(domains) != expected_domains:
        raise ValueError("Unexpected domain count")
    if set(details) != {(d, m, h) for d in DEFENSES for m in METRICS for h in domains}:
        raise ValueError("Primary table does not cover all defense/domain/metric combinations")
    if set(cohorts) != {(d, h, m) for d in MODES for h in domains for m in METRICS}:
        raise ValueError("Descriptive table does not cover all condition/domain/metric combinations")
    if set(offsets) != {(d, h) for d in DEFENSES for h in domains}:
        raise ValueError("Capture-epoch table is incomplete")

    for d in DEFENSES:
        for m in METRICS:
            s = summaries[d, m]
            if s.get("provisional", "").lower() != "false" or integer(s["domains"], "domains") != expected_domains:
                raise ValueError("Primary result is provisional or lacks domains")
            draws = integer(s["bootstrap_draws"], "bootstrap draws")
            if draws < 100 or draws != integer(quality.get("bootstrap_replicates"), "bootstrap replicates"):
                raise ValueError("Insufficient bootstrap draws")
            for stem in ("macro_ci95_sessions", "macro_ci95_domain_cluster", "pooled_ci95_sessions"):
                ci(s, stem)
            for field in ("macro_bootstrap_valid", "domain_cluster_bootstrap_valid", "pooled_bootstrap_valid"):
                if not 0 < integer(s[field], field) <= draws:
                    raise ValueError("No valid bootstrap replicates: " + field)
            base_means, def_means, ratios = [], [], []
            for h in sorted(domains):
                row = details[d, m, h]
                if integer(row["baseline_expected_n"], "baseline expected") != sessions or integer(row["defense_expected_n"], "defense expected") != sessions:
                    raise ValueError("Unexpected cohort size")
                n_b, n_d = integer(row["baseline_n"], "baseline n"), integer(row["defense_n"], "defense n")
                if not (0 < n_b <= sessions and 0 < n_d <= sessions):
                    raise ValueError("Invalid metric eligibility count")
                b, a, ratio = (num(row[k], k) for k in ("baseline_mean", "defense_mean", "overhead_pct"))
                if b <= 0 or a < 0:
                    raise ValueError("Invalid cohort mean")
                close(ratio, 100 * (a / b - 1), "domain ratio")
                close(num(row["absolute_difference"], "absolute difference"), a - b, "domain difference")
                for mode, n, mean in (("undefended", n_b, b), (d, n_d, a)):
                    dist = cohorts[mode, h, m]
                    if integer(dist["n"], "distribution n") != n or integer(dist["excluded_n"], "distribution excluded") != sessions - n:
                        raise ValueError("Cohort eligibility differs between tables")
                    close(num(dist["mean"], "cohort distribution mean"), mean, "cohort mean")
                base_means.append(b); def_means.append(a); ratios.append(ratio)
            close(num(s["macro_overhead_pct"], "macro"), statistics.mean(ratios), "macro")
            close(num(s["pooled_cohort_mean_overhead_pct"], "pooled"), 100 * (sum(def_means) / sum(base_means) - 1), "pooled")
            close(num(s["baseline_equal_domain_mean"], "baseline macro mean"), statistics.mean(base_means), "baseline macro mean")
            close(num(s["defense_equal_domain_mean"], "defense macro mean"), statistics.mean(def_means), "defense macro mean")
            close(num(s["mean_absolute_difference"], "mean absolute difference"),
                  statistics.mean(def_means) - statistics.mean(base_means), "mean absolute difference")
            for name, p in (("domain_median_pct", 50), ("domain_p05_pct", 5), ("domain_p95_pct", 95)):
                close(num(s[name], name), percentile(ratios, p), name)
    for (d, m), row in distributions.items():
        selected = [cohorts[d, h, m] for h in domains]
        n = sum(integer(x["n"], "cohort n") for x in selected)
        if integer(row["n"], "condition n") != n or integer(row["excluded_n"], "condition excluded") != expected_domains * sessions - n:
            raise ValueError("Condition distribution counts do not match cohorts")
        if n:
            weighted = sum(num(x["mean"], "mean") * integer(x["n"], "n") for x in selected) / n
            close(num(row["mean"], "condition mean"), weighted, "condition mean")
        for key in ("p50", "p95"):
            if num(row[key], key) < 0:
                raise ValueError("Negative distribution percentile")
        if num(row["p95"], "p95") < num(row["p50"], "p50"):
            raise ValueError("Distribution percentiles are out of order")
    return quality, summaries, details, distributions, offsets, shared, sensitivities, sorted(domains)


def make_report(aggregate, descriptive, figures, *, manifest, expected_domains=50, sessions=400, synthetic=False):
    if (expected_domains, sessions) != (50, 400) and not synthetic:
        raise ValueError("Reduced input sizes are permitted only for visibly marked synthetic fixtures")
    q, summaries, detail, dist, offsets, shared, sens, domains = inspect(
        aggregate, descriptive, figures, manifest=manifest,
        expected_manifest_sha=sha(manifest) if synthetic else FINAL_MANIFEST_SHA256,
        expected_domains=expected_domains, sessions=sessions)
    count = len(MODES) * expected_domains * sessions
    lines = ["# Final PCAP-derived defense overhead and practicality — draft for review", ""]
    if synthetic:
        lines += ["**SYNTHETIC FIXTURE — NOT STUDY DATA.**", ""]
    lines += [
        "**Status:** automatically assembled draft; inspect the tables, quality report, source records and figures before publication or thesis use. Classification and privacy effectiveness remain unmeasured here.", "",
        f"The input comprises {count:,} identity-verified captures, {expected_domains} resource domains, six conditions and {sessions} sessions per domain and condition. Every capture was checked against the final manifest. Per-metric exclusions are reported below; a verified capture is not by itself proof of scientific eligibility or defense fidelity.", "",
        "The primary outcomes are total observed IP datagram bytes and the first-to-last observed packet-trace span. IP totals include observed protocol traffic, fragments and retransmissions, not PCAP container headers or necessarily only application traffic. The span includes any visible setup, acknowledgments, padding or teardown. **It is not application completion, browser page-load time or the last-real-packet latency used in some papers.**", "",
        "Within each domain, overhead is `100 × (defended cohort mean / undefended cohort mean − 1)`. Captures in different conditions are separately recorded, unpaired observations; matching session numbers do not make paired traces, and observations may retain temporal dependence. The equal-domain value is the arithmetic mean of domain percentages. The pooled value is the ratio of the sums of defended and baseline domain means, giving greater weight to larger baseline values. The within-cohort intervals resample sessions separately for the observed domains and assume that this resampling is appropriate for the recorded cohort. The separate domain-cluster intervals additionally resample domains and target a hypothetical domain population; these convenience-selected domains do not guarantee representative sampling. Neither interval removes collection-time, route, workload or selection bias.", "",
        "## Study-wide primary comparisons", "",
    ]
    for metric, title in (("ip_bytes", "Observed IP traffic volume"), ("observed_span", "Observed packet-trace span")):
        lines += [f"### {title}", "", "| Defense | Equal-domain overhead (session 95% CI) | Equal-domain domain-cluster 95% CI | Pooled overhead (session 95% CI) | Equal-domain baseline mean | Equal-domain defended mean | Mean absolute difference |", "| --- | ---: | ---: | ---: | ---: | ---: | ---: |"]
        for d in DEFENSES:
            r = summaries[d, metric]
            b, a = num(r["baseline_equal_domain_mean"], "baseline"), num(r["defense_equal_domain_mean"], "defense")
            delta = num(r["mean_absolute_difference"], "difference")
            close(delta, a - b, "summary absolute difference")
            lines.append(f"| {LABELS[d]} | {pct(num(r['macro_overhead_pct'], 'macro'))} {ci(r, 'macro_ci95_sessions')} | {ci(r, 'macro_ci95_domain_cluster')} | {pct(num(r['pooled_cohort_mean_overhead_pct'], 'pooled'))} {ci(r, 'pooled_ci95_sessions')} | {amount(b, metric)} | {amount(a, metric)} | {amount(delta, metric)} |")
        lines += ["", "Percentages are ratios relative to undefended; small baseline means can produce very large ratios. The absolute differences help interpret their practical magnitude.", ""]

    lines += ["### Bootstrap replicate coverage", "", "A resampled baseline of zero makes its ratio undefined. Valid counts below disclose how many of the requested resamples contributed to each interval; undefined draws are not replaced by artificial denominators.", "", "| Defense | Metric | Equal-domain session draws | Domain-cluster draws | Pooled session draws | Requested |", "| --- | --- | ---: | ---: | ---: | ---: |"]
    for d in DEFENSES:
        for m in METRICS:
            r = summaries[d, m]
            name = "IP bytes" if m == "ip_bytes" else "Trace span"
            lines.append(f"| {LABELS[d]} | {name} | {integer(r['macro_bootstrap_valid'], 'macro valid'):,} | {integer(r['domain_cluster_bootstrap_valid'], 'cluster valid'):,} | {integer(r['pooled_bootstrap_valid'], 'pooled valid'):,} | {integer(r['bootstrap_draws'], 'draws'):,} |")
    lines.append("")

    lines += ["## Condition distributions and data quality", "", "The percentiles below describe individual captures pooled within each condition; every valid session has equal weight. They are not percentiles of per-domain overhead and do not imply paired visits.", "", "| Condition | Metric | Valid / expected captures | Excluded | Median | 95th percentile |", "| --- | --- | ---: | ---: | ---: | ---: |"]
    for d in MODES:
        for m in METRICS:
            r = dist[d, m]
            name = "IP bytes" if m == "ip_bytes" else "Trace span"
            lines.append(f"| {LABELS[d]} | {name} | {integer(r['n'], 'valid'):,} / {expected_domains * sessions:,} | {integer(r['excluded_n'], 'excluded'):,} | {amount(num(r['p50'], 'p50'), m)} | {amount(num(r['p95'], 'p95'), m)} |")
    lines += ["", "Consult `cohort-exclusions.csv`, `quality.json` and the per-domain distribution table for reasons and cohort-specific counts. Zero-denominator or completely missing cohorts must be investigated; they are not replaced by a small artificial baseline.", ""]

    lines += ["### Capture and parser quality", "", "| Condition | IP-invalid or unknown captures | Captures without verified timestamp order | Reported truncated packets | Captures with fully attributable UDP/443 candidate direction |", "| --- | ---: | ---: | ---: | ---: |"]
    for d in MODES:
        r = q['quality_by_condition'][d]
        lines.append(f"| {LABELS[d]} | {r['ip_valid_false'] + r['ip_valid_missing']:,} | {r['strict_timestamp_order_not_true']:,} | {r['truncated_packets']:,} | {r['direction_complete']:,} |")
    lines += ["", "The UDP/443 direction is a conservative observed candidate, not proof of the intended peer or of application versus padding. See the machine-readable quality report for remaining flags; packet counts and capture counts are different units.", ""]

    lines += ["## Domain variation and sensitivity", "", "| Defense | Metric | Domain median overhead | 5th–95th percentile of domain overheads | Mean ratio: median-cohort sensitivity | Mean ratio: upper-1%-trimmed sensitivity |", "| --- | --- | ---: | ---: | ---: | ---: |"]
    for d in DEFENSES:
        for m in METRICS:
            r, ss = summaries[d, m], sens[d, m]
            if integer(ss["expected_domains"], "sensitivity expected") != expected_domains:
                raise ValueError("Sensitivity expected domain count mismatch")
            def sensitivity(field):
                n = integer(ss[field + "_domains"], "sensitivity domains")
                value = ss[field + "_equal_domain_mean"]
                return "Unavailable (0 domains)" if not n else f"{pct(num(value, field))} ({n}/{expected_domains} domains)"
            name = "IP bytes" if m == "ip_bytes" else "Trace span"
            lines.append(f"| {LABELS[d]} | {name} | {pct(num(r['domain_median_pct'], 'domain median'))} | {pct(num(r['domain_p05_pct'], 'domain p05'))} to {pct(num(r['domain_p95_pct'], 'domain p95'))} | {sensitivity('median_ratio_pct')} | {sensitivity('upper_1pct_trimmed_mean_ratio_pct')} |")
    lines += ["", "The 5th–95th domain range describes observed domain-to-domain dispersion, not a confidence interval. The sensitivities compare unpaired cohort medians and separately upper-trimmed means; they do not establish causation or matched visits.", ""]

    lines += ["## Capture-time separation", "", "First-packet timestamps are PCAP clock observations. A shared UTC day does not imply the same hour, response body, route or experimental condition. Clock error, post-capture sorting and noncontemporaneous live resources remain important limitations.", "", "| Defense | Domains with usable offsets | Domains with any shared UTC day | Median of domain median-start offsets | Range of domain median-start offsets |", "| --- | ---: | ---: | ---: | ---: |"]
    for d in DEFENSES:
        group = [offsets[d, h] for h in domains]
        valid = [num(r["median_offset_days"], "median offset") for r in group if r.get("median_offset_days", "") != ""]
        count_shared = sum(integer(r["shared_utc_days"], "shared days") > 0 for r in group if r.get("shared_utc_days", "") != "")
        if not valid:
            lines.append(f"| {LABELS[d]} | 0/{expected_domains} | {count_shared}/{expected_domains} | Unavailable | Unavailable |")
        else:
            lines.append(f"| {LABELS[d]} | {len(valid)}/{expected_domains} | {count_shared}/{expected_domains} | {statistics.median(valid):+,.2f} days | {min(valid):+,.2f} to {max(valid):+,.2f} days |")
    lines += ["", "Offsets are defended minus undefended cohort median first-packet times. Negative values mean the defended cohort was observed earlier under the recorded clocks. The range-overlap and shared-day diagnostics are not proof of equivalent content or unconfounded comparisons.", "", "### Exploratory shared-UTC-day sensitivity", "", "| Defense | Metric | Eligible domains | Defended / baseline sessions | Equal-domain mean overhead |", "| --- | --- | ---: | ---: | ---: |"]
    for d in DEFENSES:
        for m in METRICS:
            r = shared[d, m]
            n = integer(r["eligible_domains"], "shared eligible domains")
            if n > expected_domains or integer(r["expected_domains"], "shared expected") != expected_domains:
                raise ValueError("Invalid shared-day domain count")
            value = "Unavailable" if not n else pct(num(r["equal_domain_mean_overhead_pct"], "shared-day result"))
            name = "IP bytes" if m == "ip_bytes" else "Trace span"
            lines.append(f"| {LABELS[d]} | {name} | {n}/{expected_domains} | {integer(r['defense_sessions_in_eligible_domains'], 'shared defense sessions'):,} / {integer(r['baseline_sessions_in_eligible_domains'], 'shared baseline sessions'):,} | {value} |")
    lines += ["", "The shared-day subset is exploratory and weights days by the available sessions. It may exclude most domains or select unrepresentative traffic; it is not a causal adjustment or session pairing.", ""]

    lines += ["## Per-defense interpretation", "", "Read each condition's measured row together with its implementation and failure evidence. Historical cases provide context; they are not substituted for final-PCAP measurements or treated as final-cohort failure rates.", ""]
    for d in DEFENSES:
        ip, span = summaries[d, "ip_bytes"], summaries[d, "observed_span"]
        lines += [f"### {LABELS[d]}", "", f"The equal-domain IP-byte comparison is {pct(num(ip['macro_overhead_pct'], 'IP overhead'))} and the observed-span comparison is {pct(num(span['macro_overhead_pct'], 'span overhead'))}. Across domains, the IP-byte overhead's observed 5th–95th percentile range is {pct(num(ip['domain_p05_pct'], 'IP domain p05'))} to {pct(num(ip['domain_p95_pct'], 'IP domain p95'))}; the observed-span range is {pct(num(span['domain_p05_pct'], 'span domain p05'))} to {pct(num(span['domain_p95_pct'], 'span domain p95'))}. These describe this observed resource-domain dataset; they are neither an application-delay claim nor evidence of classifier resistance.", "", f"{PRACTICALITY[d]} The [practicality note]({NOTES[d]}) documents the mechanism, implementation-specific settings, dated acquisition difficulties and limitations.", ""]
    lines += [
        "## Domain-level primary estimates", "",
        "Each entry is a ratio of separately recorded domain-cohort means. See the machine-readable tables for confidence intervals, absolute means, exclusions and sensitivities.", "",
    ]
    for m, title in (("ip_bytes", "IP-byte overhead by domain"), ("observed_span", "Observed trace-span overhead by domain")):
        lines += [f"### {title}", "", "| Domain | FRONT | Tamaraw | BuFLO | CS-BuFLO | WTF-PAD |", "| --- | ---: | ---: | ---: | ---: | ---: |"]
        for h in domains:
            safe = h.replace("|", "\\|").replace("\n", " ")
            vals = " | ".join(pct(num(detail[d, m, h]["overhead_pct"], "domain overhead")) for d in DEFENSES)
            lines.append(f"| `{safe}` | {vals} |")
        lines.append("")
    lines += [
        "## Figures, data and reproducibility", "",
        "The reviewed figure bundle contains `01-overall-overheads` and `02-domain-spread` in SVG and PDF. Their whiskers and axes follow the labelled fixed-domain bootstrap and domain-dispersion definitions; they do not represent classification accuracy.", "",
        f"The manifest SHA-256 is `{q['manifest_sha256']}` and the canonical metric-row snapshot SHA-256 is `{q['metric_rows_content_sha256']}`. The aggregate used {integer(q['bootstrap_replicates'], 'bootstrap replicates'):,} resamples and seed `{integer(q['seed'], 'seed')}`. Recreate the measurements and tables using the [public PCAP toolkit](https://github.com/kaisequeira/neqo-qcsd-lab/tree/main/tools/pcap-overhead) and [final handoff](https://drive.google.com/drive/folders/1mE0wM6ZJ7AoJli-9d0ckRnShO2bWVdNQ). The [methods and literature reference](https://drive.google.com/file/d/1J_WjNax8tIs57md4HN8bFKD32C8V2sg4/view) explains the estimands and primary papers.", "",
        "Do not infer a privacy–cost ranking until the future classification study has actually been performed with its threat model, split, metrics and uncertainty documented. Recorded acquisition failures also have different denominators from the accepted final capture inventory; use the per-defense notes rather than treating historical pilot counts as final rates.", "",
    ]
    return "\n".join(lines)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--aggregate", type=Path, required=True)
    p.add_argument("--descriptive", type=Path, required=True)
    p.add_argument("--figures", type=Path, required=True)
    p.add_argument("--manifest", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    if args.output.exists():
        raise ValueError("Output already exists; refusing to overwrite")
    content = make_report(args.aggregate, args.descriptive, args.figures, manifest=args.manifest)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8", newline="\n") as f:
        f.write(content)
    print(json.dumps({"status": "review_draft", "sha256": sha(args.output)}))


if __name__ == "__main__":
    main()
