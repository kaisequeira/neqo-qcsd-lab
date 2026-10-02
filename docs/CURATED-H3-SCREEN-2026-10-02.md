# What happened to the 73 curated site candidates

**Diagnostic screen on 2 October 2026. Zero acquisition and capture credit.**
The [source JSON](../config/curated-sources/crux-73-v1.raw.json) has 73
distinct site keys. We tested `https://domain/` with the v147 Neqo HTTP/3
client, using a known working HTTP/3 control before and after each group of
ten. All eight control pairs passed. The three create-only local logs are
`../diagnostic-rehearsals/curated-h3-20261002/curated-h3-0-9.jsonl`,
`curated-h3-10-49.jsonl`, and `curated-h3-50-72.jsonl` in the same sibling
directory. Their SHA-256 hashes are respectively
`5789f8324be30a886b752069603e2238e504b68aee8639c92b5f699e62df1ba5`,
`ffb4eacb9ce914b847f073d2821154a71bd2a3f2bd2449daa26c3387fe1ca82a`,
and `85a12896fb1682067c7d652ba070d08e6efbba5f9f6aeaee4b58dbf2f92c49e1`.

| Root check outcome | Count | Meaning |
|---|---:|---|
| Clear HTTP/3 success | 30 | The homepage probe returned a `known_valid` response. The site is **not yet an eligible class**: browser graph, live cross-origin resources, content stability and safety still need checking. |
| Ambiguous | 28 | No accepted root result. Twenty-one commands returned a resource marked `known_valid=false`; six ended with a peer `336` close; one public-origin DNS policy rejected a non-public answer. These are not proven site failures. |
| Peer `296` close | 6 | The peer closed the QUIC/TLS connection before an accepted run completed. An inner page or later retry might differ. |
| 12-second timeout | 2 | The bounded root probe expired. It does not establish permanent lack of HTTP/3. |
| Skipped before network | 7 | The existing domain-safety rule marked them for exclusion from this screen. |

## Exact domains and observed problem

| Observation | Domains |
|---|---|
| Peer `296` close | `444.hu`, `pimpbunny.com`, `search-fast.org`, `wayground.com`, `www.programme-television.org`, `xoilacxtb.tv` |
| Exit 0 but root resource `known_valid=false` | `angkanet26.com`, `bollyflix.af`, `calamitymod.wiki.gg`, `ca.pinterest.com`, `deodap.in`, `innovist.com`, `m.youtube.com`, `news.google.com`, `redtape.com`, `timesofindia.indiatimes.com`, `www.clarin.com`, `www.gharsoaps.shop`, `www.giva.co`, `www.goodreturns.in`, `www.gooutdoors.co.uk`, `www.limelight.pk`, `www.tgju.org`, `www.theguardian.com`, `www.xbox.com`, `www.zappos.com`, `zerolifestyle.co` |
| Peer `336` close | `m.fmkorea.com`, `weather.com`, `www.aajtak.in`, `www.cronista.com`, `www.fmkorea.com`, `www.msn.com` |
| Public-origin policy rejected a non-public DNS answer | `variety.com` |
| 12-second timeout | `www.diretta.it`, `www.flashscore.com.ua` |
| Skipped by automatic safety policy | `bookmark.xxx`, `doradobet.com`, `es.anysex.com`, `incontriamoci.xxx`, `pornone.com`, `xxxvideo.link`, `zbporn.tv` |

The 30 clear root successes were `chaturbate.com`, `discord.com`,
`dokterjav.com`, `en-miwg.comfortweather.com`, `kir2kos.net`, `ph.747.live`,
`poki.com`, `toom.de`, `www.3bmeteo.com`, `www.acgxmh.com`, `www.albumaty.com`,
`www.alibaba.com`, `www.bing.com`, `www.dictionary.com`, `www.euronews.com`,
`www.flashscore.com.mx`, `www.flashscore.com`,
`www.futura-sciences.com`, `www.haberler.com`, `www.idrlabs.com`,
`www.jutarnji.hr`, `www.khaleejtimes.com`, `www.sacnilk.com`,
`www.savana.com`, `www.sondakika.com`, `www.tippmixpro.hu`,
`www.tomsguide.com`, `www.tori.fi`, `www.weerplaza.nl`, and
`www.youjizz.com`. Some are plainly unsuitable for the intended public-page
study despite not being flagged by the current automatic policy. Human safety
review precedes browser preparation; a technical root success cannot override
that review.

Only **14** of the 30 root successes have two or more resource-host groups in
the supplied JSON. Those groups are historical hints, not proof that the
current page loads a second origin. These v4 homepage and hint counts do not
establish how many pages can meet the current v5 selected-page rule: a recorded
ambiguous homepage may still yield a separately controlled HTTP/3 pass on its
selected page. The [rapid plan](RAPID-CLASS-STUDY.md) keeps 50 as the formal
target, begins diagnostic work with suitable clear successes, and includes a
frozen fallback catalogue. **Fifty-site eligibility remains unproven.**

The source file and [compact receipt](../config/curated-sources/crux-73-v1.source.json)
support **73 distinct `crUX_domain` entries**, **63 entries with at least one
listed resource**, **57 with a listed resource and no automatic safety flag**,
and **50 with a different-host hint and no automatic safety flag**. We found
no documented calculation yielding the earlier claim of **58 unique classes**.
These different counts must not be interchanged with live eligibility.

## First browser follow-ups

Two clear root successes were tried through the separate direct pinned-browser
page route. `www.idrlabs.com` reached the browser but did not pass the 30-second
passive-render quiescence check ([local diagnostic receipt described in the
evidence index](EVIDENCE-INDEX.md)). `www.weerplaza.nl` stopped when the
discovery event audit could not prove one contiguous primary redirect chain
(local receipt SHA-256
`dbd9c827a12ceeaa6a863b6b25e145f9dc04a09e1e09cf5ddf0841472771975d`).
Both remain unadmitted. Their clear homepage HTTP/3 responses must not be
mistaken for complete capture-ready page graphs.
`www.sacnilk.com` then completed direct browser discovery with 42 returned
resources and 14 observed origins, but its initial three-origin allowlist left
14 exclusions. It needs complete-origin convergence and replay before any
site admission. A second pass admitting the observed origins failed the
30-second passive-render quiescence check and its CDP frame-detachment audit.
This remains a useful working lead, not an accepted class.
`www.3bmeteo.com` then completed a bounded direct-browser discovery in 25
seconds, recording 132 requests and 106 resources across 17 observed origins.
Its initial two-origin allowlist left 22 exclusions, including unapproved
third-party requests. This shows that browser discovery can complete on a
curated page, but it is still a lead: full-origin convergence, replay and
safety review have not produced an admitted workload.
A second pass approved the first pass's 13 expandable origins and returned
136 resources, yet eight GETs still came from unapproved origins, including
two newly observed analytics hosts. One host contained a changing timestamp
in its name. Full-origin convergence therefore remains unproven, and this
page cannot be counted under the current complete-graph rule.

Six more clear-root candidates received bounded direct-browser checks in the
v147 preparation image. Their create-only JSON receipts are under
`../diagnostic-rehearsals/curated-direct-20261002/`; the common run log has
SHA-256 `18e16b4b1e69d647296d5129610d844f6f7758a05fb7647497077a7a7456891b`.

| Candidate | Browser result | Receipt SHA-256 |
|---|---|---|
| `ca.pinterest.com` | Failed 30-second passive-render quiescence. | `abce7aa1573c07ab55d23f4de622cd405e1108b5c7217464c4a5978d75e819fd` |
| `discord.com` | CDP rejected a Chromium loading failure with missing error text. | `b705ed3e17468cf200b467389c3e3656dccd1edf41332c31821538f93b3b297b` |
| `en-miwg.comfortweather.com` | CDP HTTP observation and request-stage interception ledgers differed. | `f25f5e27561eb9337c831caaf30402307d91512c1107c62ec12c5a778523fed4` |
| `poki.com` | Discovery completed: 259 resources, five observed origins, one unapproved-origin GET and one unsafe POST. It needs a second origin pass and replay. | `0d8121a6daf2073ae7cdd9d0ae9e3c50567fcca48a13435ccd91126d02f32e38` |
| `toom.de` | Discovery completed: 48 resources, 41 unapproved-origin requests and two unsafe OPTIONS requests. It needs substantial origin convergence. | `97e00217fb39bce49043427a54664cfc26d206494452b722ffe4994942bf069a` |
| `www.alibaba.com` | CDP detected a related target detaching while work remained pending. | `41697c825a2ba2c750059724fc4bc62873b1057c15050b7be14238457b3395ac` |

These are diagnostic page leads and failures. None is a verified preparation
or an admitted class. A second `poki.com` pass approved all four origins from
the first pass. It completed in 19 seconds with **268 resources and 280
observed requests** across five observed origins. There were **no unapproved
GETs**; the sole exclusion was an unsafe analytics POST to `t.poki.io`.
The create-only second-pass receipt is
`../diagnostic-rehearsals/curated-direct-20261002/poki-com-discover-002.json`
(SHA-256 `dabb346dc628ff99447768d274d824c60878a4bd10665dde70853f64b009cd51`).
This made Poki a preparation/replay lead, not an admitted site. A bounded,
zero-credit preparation attempt then failed in about 20 seconds at the
complete-coverage HTTP/3 preflight: resource 253,
`https://poki-auth.poki.com/sessions/whoami`, was unavailable to Neqo.
Stability replay never began and no workload was written. The create-only
failure receipt is
`../diagnostic-rehearsals/curated-direct-20261002/poki-com-prepare-001.json`
(SHA-256 `e2c9d75b07b5976a0cd2ab6d461ff23a1021fa890a43a904fc86fa749002b39b`).
Poki remains unadmitted under the current complete-resource rule. This is a
diagnosed resource failure, not proof that the domain can never work.
A separate zero-credit test used the existing generic preparer with incomplete
coverage allowed and two Neqo stability runs. It still failed: the main
document and 52 other retained resources changed or failed across the runs.
No workload was written. Its create-only receipt is
`../diagnostic-rehearsals/curated-direct-20261002/poki-subset-001.json`
(SHA-256 `e57b7dfb36ee9aa4f32597966b88608a2a7b1e417669e6d5cd411da25f23c82c`).
This diagnostic does not amend the v4 study rules or establish that simply
downgrading complete coverage would make Poki usable.

`www.haberler.com` was another clear-root, two-origin-hint candidate. Its
bounded direct browser check stopped at the 30-second passive-render
quiescence condition, before a resource graph could be admitted. The
create-only receipt is
`../diagnostic-rehearsals/curated-direct-20261002/haberler-discover-001.json`
(SHA-256 `9e487db50a9be915ed8b2098c002fa3dfbd90c5461742ea78df135eaac08745d`).
It remains a diagnostic failure, not a permanent domain classification.

## Post-freeze v4 screen

After the [v4 rapid profile](../config/curated-sources/crux73-tranco600-rapid-v4.profile.json)
was frozen, the same v147 preparation image repeated the controlled root
screen in two create-only slices. The logs are local at
`../diagnostic-rehearsals/curated-h3-v4-20261002/curated-h3-v4-0-39.jsonl`
and `curated-h3-v4-40-72.jsonl`, with SHA-256 hashes
`1b05846ecfa99f22e9e422303cde4f56dce44b1723d3932a1889c1b769906c5e`
and `7f8cfbc34697fef22cc6398f7aa416271e0b75875294637f1b7b39baaaeb7881`.
The profile's independent log verifier reopened both files against the tracked
raw source, source receipt, v147 build receipt, preparation-image digest,
mounted module hashes and profile freeze time. It verified all **73 ordered
first-screen decisions**, with eight passing control pairs: **30 clear H3,
28 ambiguous, six peer TLS handshake failures, two timeouts and seven
automatic safety skips**. `ca.pinterest.com` became a clear root success;
`kir2kos.net` no longer was. This illustrates why the first live result is
bound to a specific attempt instead of being inferred from the earlier screen.
The v4 screen grants no site admission; safety review, full browser discovery,
resource replay and cross-origin checks remain outstanding.

## First Tranco fallback batch: diagnostic, no v4 screen credit

The frozen profile orders the 600 Tranco candidates after the 73 supplied
entries. The first fallback batch attempted global candidate positions
**74–83** between two `known_valid` HTTP/3 control responses. The create-only
local log is
`../diagnostic-rehearsals/rapid-fallback-h3-20261002/fallback-000-009.jsonl`
(SHA-256 `20da871f823f9b7bcd8cd9e3103adc8acee8c7da2f77919719d0539076e24b75`).
Its producer recorded ten attempted targets and a complete batch, with **zero
clear HTTP/3 roots, six timeouts and four ambiguous observations**:

| Raw observation | Candidate IDs | Count |
|---|---|---:|
| Twelve-second root timeout | `tranco-0000697`, `tranco-0000984`, `tranco-0000220`, `tranco-0000628`, `tranco-0000280`, `tranco-0000709` | 6 |
| Local DNS resolver error | `tranco-0000837`, `tranco-0000632`, `tranco-0000476` | 3 |
| Response marked `known_valid=false` | `tranco-0000553` | 1 |

The independent v4 verifier rejects the log at the first generic local DNS
resolver error, at global position 76 (`tranco-0000837`). The frozen v4
policy has no terminal class for that result. Therefore the producer's
`batch-complete` record does **not** establish ten verified first-screen
decisions, site exclusions or an admitted fallback site. The log remains
diagnostic and zero credit. The frozen prospective
[v5 profile](../config/curated-sources/crux73-tranco600-rapid-v5.profile.json)
classifies the exact `gaierror -2` name-not-found result as an operational
deferral and allows a separately controlled selected-page HTTP/3 pass after
an ambiguous homepage. It cannot retroactively promote the v4 batch. A
selected page still needs a complete stable replay and live cross-origin
resource. **0/50 rapid-study sites are admitted.**

## Fresh v5 fallback screen: ten verified first decisions

A fresh create-only v5 survey repeated the first fallback slice after the
v5 profile freeze. Its local log is
`../diagnostic-rehearsals/rapid-fallback-h3-v5-20261002-001/fallback-000-009.jsonl`
(SHA-256 `852599148d9e473383bca8713ddb922460e2c2dadfcf1f54526a339a4581767f`).
It binds the v5 profile SHA-256
`f7eb0228a06429cc2ae91d0f9d52577399e15b68f4915d41cb60291445542b60`,
preparation image `sha256:b57eb71a063207341aadd894d0a72fa6a865aee3f557c8b6e098cff4fea2bed8`,
survey-tool hash `bc66c804123053c8c7b662e62a53281b5cb0234944d895da0781455769a002f4`,
and profile-module hash `524673be1db426acb94fbff89f6e45a3da5ed7573f83409ee1ce43c0f58e1944`.
The independent `verify_v5_fallback_h3_survey_logs` check accepted exactly
fallback indices **0–9**, global positions **74–83**, with `known_valid`
controls before and after. The outcomes were **six timeouts**, **three exact
DNS-name-not-found operational deferrals**, and **one response-known-invalid
ambiguous result**. None was a clear HTTP/3 homepage success.

These are **ten verified v5 first-screen decisions**. They are not page
preparations, selected-page HTTP/3 proofs, eligible sites or study traces.
An ambiguous or deferred homepage may be followed by the distinct controlled
selected-page check allowed by v5; no such proof or admission is claimed for
this batch. The earlier v4 batch remains rejected and diagnostic, with no
retroactive credit. **0/50 sites admitted; 0/16,000 formal traces accepted.**
