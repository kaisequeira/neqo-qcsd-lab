"""Exact append-only retirement of three two-phase CS211 clock refusals.

Old SQL, attempts, measurements and frozen manifests are never changed.  This
is a separately typed admission, not integrity withdrawal or raw qualification.
The saved refusal bytes are fixed SOURCE inputs; a real current standard parent,
fresh prepared writer, head publication and its own pilots remain mandatory.
"""
from __future__ import annotations

from copy import deepcopy
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
from types import ModuleType
import zlib

CHANGE = "scientific-refusal-retirement-CS211-three-v1"
DECLARATION = "qcsd-resource-domain-CS211-three-scientific-refusal-declaration-v1"
JOURNAL = "qcsd-resource-domain-CS211-three-scientific-refusal-journal-v1"
SCOPE = "qcsd-resource-domain-CS211-three-retired-row-scope-v1"
COMPOSITION = "qcsd-resource-domain-runtime-cohort-active-and-historical-composition-v2"
PARTITION_TYPE = "qcsd-resource-domain-qualified-pending-scientific-retirement-partition-v1"
EXCLUSION = "qcsd-resource-domain-CS211-three-scientific-refusal-exclusion-v1"
EVIDENCE = "qcsd-resource-domain-CS211-three-fixed-proof-evidence-v1"
ERROR = "study handoff cs_buflo incoming controller terminal time differs from translated credit consumption"
CELLS = (("ph.747.live", "cs-buflo"), ("zerolifestyle.co", "cs-buflo"))
ATTEMPTS = ("d5d053ea73514a55982e4060d4bcdd0e", "0b687c2f82cd499cbf3fb5e934663f55", "34f28dfb23cf41fe9e52632b600e7875")
ORDINALS = {407: ATTEMPTS[0], 412: ATTEMPTS[1], 583: ATTEMPTS[2]}
WORKER = "a497929dda02d41e426efeb54c35f50aa4338f0d65257bb78be0a1adab88cdf0"
CORRECTION = "6f8d63659a8f4e6c50e92db3d566718f771a85a3f91bba2bf8028f6f60046155"
SETUP = Path("/home/joshkai/neqo-obfuscation/setup")
HOST_SETUP = Path("/Users/joshkai/Documents/neqo-obfuscation/mac-migration-20261009/setup")
AUTHORITY = ("ROOT_Source095_public094_qualified_deferred_authority_001.py", "4bdc483de3276092baca679f2f6b670c1a8dd4c1cb49dd1e8fd675459984c855")
PARTITION = ("ROOT_Source102_catalog013_pending587_partition_001.py", "10496bf39e705ca4a6abee89652e12923c335a679311dddbb18be9a027018afb")

# The author fills these three literal registries from authenticated immutable
# HOST exports, without importing the SDK. No future execution identity belongs
# in them. Runtime helpers refuse an incomplete registry.
FIXED_FILES = [{'guest_path': '/home/joshkai/neqo-obfuscation/setup/source102-catalog013-CS096211-corrected004-receipt-proof-001/production-phase-1-cs-096-e3e7a93bf96f416692fb67b2e84d539c.json', 'sha256': 'd408a8a5ed50c9003c1407b2e0fc94c0cfcdbf350480a0fa1dfbf8bb495b60f0', 'bytes': 86421}, {'guest_path': '/home/joshkai/neqo-obfuscation/setup/source102-catalog013-CS096211-corrected004-receipt-proof-001/production-phase-2-cs-096-8db92bc92ce246f3ae38cea692745e15.json', 'sha256': '5a76614538a51df5da2a644400653debb129fe91225a30cdda389540af5d18dc', 'bytes': 86421}, {'guest_path': '/home/joshkai/neqo-obfuscation/setup/source102-catalog013-CS096211-corrected004-receipt-proof-001/pool-70e163f481e54439b53a7fd4e3dc3cc9/receipt-000407.json', 'sha256': '5c350755b380e51a59de206cfedcff4acfcd92c7c0ddf0f8853ed6bd99f6175b', 'bytes': 36905}, {'guest_path': '/home/joshkai/neqo-obfuscation/setup/source102-catalog013-CS096211-corrected004-receipt-proof-001/pool-2f43f2ff97f940b7b4250c610da2fa64/receipt-000412.json', 'sha256': 'bf3e89d54961245d554d0bc2a1f69507b30e903fad93e3393a062c72042d95b3', 'bytes': 36905}, {'guest_path': '/home/joshkai/neqo-obfuscation/setup/source102-catalog013-CS096211-corrected004-receipt-proof-001/pool-e3a19e8afc49452d8416e8967c0f34ff/receipt-000432.json', 'sha256': 'a886ee6845d3cdabcabc76d6e157a1a6d59b908533452f3198321ded7604b547', 'bytes': 53732}, {'guest_path': '/home/joshkai/neqo-obfuscation/setup/source102-catalog013-CS096211-corrected004-receipt-proof-001/pool-e3a19e8afc49452d8416e8967c0f34ff/receipt-000583.json', 'sha256': '3ed933467d1daec76ec2280c5735b36856b73abbd25d053013748a93a6d5aec9', 'bytes': 36939}, {'guest_path': '/home/joshkai/neqo-obfuscation/setup/source102-catalog013-CS096211-corrected004-receipt-proof-001/pool-b42a2c2804db4bc7be1cb6c8a0a57f29/receipt-000407.json', 'sha256': 'a2a28197df48b3a6580de6b0c498f9edaec2225e7677e2e918a454ce54c30230', 'bytes': 36905}, {'guest_path': '/home/joshkai/neqo-obfuscation/setup/source102-catalog013-CS096211-corrected004-receipt-proof-001/pool-f6f9eaeb96e54028a5fdf92a8e013928/receipt-000412.json', 'sha256': '8482a9ad1a80daf1464e527eb138f624818d91a177b88c048575f06ff5ad2c97', 'bytes': 36905}, {'guest_path': '/home/joshkai/neqo-obfuscation/setup/source102-catalog013-CS096211-corrected004-receipt-proof-001/pool-c37260d5390040ada77b2c3a09a5b29f/receipt-000432.json', 'sha256': '251938529856712c7ed7903a82c4cf05ab606af47c169f644436eba6259d6ab3', 'bytes': 53732}, {'guest_path': '/home/joshkai/neqo-obfuscation/setup/source102-catalog013-CS096211-corrected004-receipt-proof-001/pool-c37260d5390040ada77b2c3a09a5b29f/receipt-000583.json', 'sha256': '1f71a40fe9793bd161b94a4e8af0ff2686c08448b8f87243f9a1625d2be21cad', 'bytes': 36939}, {'guest_path': '/home/joshkai/neqo-obfuscation/setup/source102-catalog013-CS096211-corrected004-receipt-proof-001/pool-70e163f481e54439b53a7fd4e3dc3cc9/closed.json', 'sha256': '8e025f9262cb6ce6c7a257147ae4b6852b1c2748646155d2db5b0f6f3d68eda0', 'bytes': 44970}, {'guest_path': '/home/joshkai/neqo-obfuscation/setup/source102-catalog013-CS096211-corrected004-receipt-proof-001/pool-2f43f2ff97f940b7b4250c610da2fa64/closed.json', 'sha256': 'fa1e94204896751f11c82593bfd70d5a6d863abbaba6561cca62cec29e76019e', 'bytes': 36788}, {'guest_path': '/home/joshkai/neqo-obfuscation/setup/source102-catalog013-CS096211-corrected004-receipt-proof-001/pool-e3a19e8afc49452d8416e8967c0f34ff/closed.json', 'sha256': '0ad401194f578b3460514702e1551bf1b0fb49387d9645cb7ada9f0602f2b9b4', 'bytes': 80727}, {'guest_path': '/home/joshkai/neqo-obfuscation/setup/source102-catalog013-CS096211-corrected004-receipt-proof-001/pool-b42a2c2804db4bc7be1cb6c8a0a57f29/closed.json', 'sha256': '1bc83e4bc49d62fc461f7c58cf36beef1badbaed659cbc4df42e7816ab4c1e6b', 'bytes': 44970}, {'guest_path': '/home/joshkai/neqo-obfuscation/setup/source102-catalog013-CS096211-corrected004-receipt-proof-001/pool-f6f9eaeb96e54028a5fdf92a8e013928/closed.json', 'sha256': 'ede49a0ad439208199769abf293de3ce2dcb10a03dbbaaf164a9fabe5b140cde', 'bytes': 36788}, {'guest_path': '/home/joshkai/neqo-obfuscation/setup/source102-catalog013-CS096211-corrected004-receipt-proof-001/pool-c37260d5390040ada77b2c3a09a5b29f/closed.json', 'sha256': '1daf8c969e9d5d9c3a8fd3941478aeacff7ed311057ae0605f9a726a45c761dd', 'bytes': 80727}]
FIXED_ROWS = [{'accepted_row_sha256': 'fa0ab307211762defe3f28f59c1141b96ca85bb4760a4eba76a833743a2fc284', 'attempt_id': 'd5d053ea73514a55982e4060d4bcdd0e', 'cohort_id': '59e4965a385cc6d626fa1ad94b87ea364f6a5e0dddfe80bf5a813ea043a61a32', 'five_tuple': '[\n  "10.232.0.203",\n  54454,\n  "172.67.141.96",\n  443,\n  17\n]\n', 'hostname': 'ph.747.live', 'mode': 'cs-buflo', 'native': ['ea213fc570e8a09aa813548e6ce1b6d433fec4817e7911cf21cb08123a3356c6', 'linux/arm64', '4919a0976b30933f81f5fa39bf557fd63e9895aa'], 'receipt_path': 'corpus/ph.747.live/cs-buflo/session-000137/session.json', 'receipt_sha256': '4724a145c5de155950df4f57da070deedddf27970e01bcbfd0ddc6abd0f485bc', 'root': '/mnt/lima-neqo-data/neqo-obfuscation/study/native131-source094-affected-eleven-CS-original50-runtime-cohort-002', 'slot': 137, 'verifier_sha256': 'b762657c74120761955bc66edce5fdd4dff8fa507f5973203bead399c3c9e52b'}, {'accepted_row_sha256': '1bae921c485d1a3bf765971f4009a34dffe3992d4f33b9605b528ecaf91f9803', 'attempt_id': '0b687c2f82cd499cbf3fb5e934663f55', 'cohort_id': '59e4965a385cc6d626fa1ad94b87ea364f6a5e0dddfe80bf5a813ea043a61a32', 'five_tuple': '[\n  "10.232.0.203",\n  46900,\n  "172.67.141.96",\n  443,\n  17\n]\n', 'hostname': 'ph.747.live', 'mode': 'cs-buflo', 'native': ['ea213fc570e8a09aa813548e6ce1b6d433fec4817e7911cf21cb08123a3356c6', 'linux/arm64', '4919a0976b30933f81f5fa39bf557fd63e9895aa'], 'receipt_path': 'corpus/ph.747.live/cs-buflo/session-000142/session.json', 'receipt_sha256': 'aabd90956efdb5084cffb8be2e38bd4921a3189ef0cd7e2dde52bb03381ca358', 'root': '/mnt/lima-neqo-data/neqo-obfuscation/study/native131-source094-affected-eleven-CS-original50-runtime-cohort-002', 'slot': 142, 'verifier_sha256': 'b762657c74120761955bc66edce5fdd4dff8fa507f5973203bead399c3c9e52b'}, {'accepted_row_sha256': '892d28a8de5bd60c19d2a7aadb4fe8b21ee88948c344dad370c6fe61d117343b', 'attempt_id': '34f28dfb23cf41fe9e52632b600e7875', 'cohort_id': '74237ded4561b2b0521915aa53931b1554879b9da8524ebce912f34672103fee', 'five_tuple': '[\n  "10.232.1.139",\n  34726,\n  "23.227.38.65",\n  443,\n  17\n]\n', 'hostname': 'zerolifestyle.co', 'mode': 'cs-buflo', 'native': ['ea213fc570e8a09aa813548e6ce1b6d433fec4817e7911cf21cb08123a3356c6', 'linux/arm64', '4919a0976b30933f81f5fa39bf557fd63e9895aa'], 'receipt_path': 'corpus/zerolifestyle.co/cs-buflo/session-000254/session.json', 'receipt_sha256': 'b6d84b45206d4c98a7487f7102d7e0eaa10c595f27c59b89d4b15a9ff0efb72f', 'root': '/mnt/lima-neqo-data/neqo-obfuscation/study/native131-source094-affected-eleven-CS-original50-runtime-cohort-002', 'slot': 254, 'verifier_sha256': 'b762657c74120761955bc66edce5fdd4dff8fa507f5973203bead399c3c9e52b'}]
PARENT_SOURCES = {'ROOT_Source102_catalog017_closed_partial_refusal45_recovery_001.py': {'consumer': ('ROOT_Source102_catalog017_closed_partial_refusal45_recovery_001.py', '82bf31fe643c55ef021e111419d1c918bead788b42698632f624478861d35906'), 'workflow': ('ROOT_Source102_catalog017_closed_partial_refusal45_recovery_001.py', '82bf31fe643c55ef021e111419d1c918bead788b42698632f624478861d35906'), 'checkpoint_type': 'qcsd-ROOT-Source102-catalog017-partial-refusal45-recovered-completed-checkpoint-v1', 'transfer_type': 'qcsd-ROOT-Source102-catalog017-partial-refusal45-recovered-closed-checkpoint-transfer-v1', 'graph': '0911d3f1cdbfbd56c3596a76e47f61fe5591d5e8caa07e7c51b53fc8afa78905', 'contract': 'b762657c74120761955bc66edce5fdd4dff8fa507f5973203bead399c3c9e52b'}, 'ROOT_Source102_catalog013_durable_salvage_promotion_workflow_002.py': {'consumer': ('ROOT_Source102_catalog013_durable_salvage_promotion_workflow_002.py', '3268b5fd4ec9a55b9b7742be28887226cdcccae47d114b0db5e5d7024aa7a844'), 'workflow': ('ROOT_Source102_catalog013_durable_salvage_promotion_workflow_002.py', '3268b5fd4ec9a55b9b7742be28887226cdcccae47d114b0db5e5d7024aa7a844'), 'checkpoint_type': 'qcsd-ROOT-Source102-C13-durable-two-proof-subset-promotion-completed-checkpoint-v1', 'transfer_type': 'qcsd-ROOT-Source102-C13-durable-two-proof-subset-promotion-closed-checkpoint-transfer-v1', 'graph': '0911d3f1cdbfbd56c3596a76e47f61fe5591d5e8caa07e7c51b53fc8afa78905', 'contract': 'b762657c74120761955bc66edce5fdd4dff8fa507f5973203bead399c3c9e52b'}, 'ROOT_Source109_catalog_existing_members_checkpoint_consumer_019.py': {'consumer': ('ROOT_Source109_catalog_existing_members_checkpoint_consumer_019.py', '903965f62e0246c50437b5849425b02a120b3a161bf59ce8f90204c5678775db'), 'workflow': ('ROOT_Source109_catalog_existing_members_new_only_workflow_019.py', 'da9d396dc0dd4b270610dd996375e347139f666ef6fb52bcb9fc017849eb75c7'), 'checkpoint_type': 'qcsd-ROOT-Source101-catalog-multiwriter-completed-checkpoint-v1', 'transfer_type': 'qcsd-ROOT-Source101-catalog-closed-completed-checkpoint-transfer-v1', 'graph': '0911d3f1cdbfbd56c3596a76e47f61fe5591d5e8caa07e7c51b53fc8afa78905', 'contract': 'b762657c74120761955bc66edce5fdd4dff8fa507f5973203bead399c3c9e52b'}, 'ROOT_Source109_catalog019_interrupted_outer_closed_capture_recovery_002.py': {'consumer': ('ROOT_Source109_catalog019_interrupted_outer_closed_capture_recovery_002.py', 'ba6101c1b4bd2e4e204efb2fec1854e6a37986ecaa37d9444409dccbfa93c4d0'), 'workflow': ('ROOT_Source109_catalog019_interrupted_outer_closed_capture_recovery_002.py', 'ba6101c1b4bd2e4e204efb2fec1854e6a37986ecaa37d9444409dccbfa93c4d0'), 'checkpoint_type': 'qcsd-ROOT-Source109-catalog019-interrupted-outer-recovered-completed-checkpoint-v1', 'transfer_type': 'qcsd-ROOT-Source109-catalog019-interrupted-outer-recovered-closed-checkpoint-transfer-v1', 'graph': '0911d3f1cdbfbd56c3596a76e47f61fe5591d5e8caa07e7c51b53fc8afa78905', 'contract': 'b762657c74120761955bc66edce5fdd4dff8fa507f5973203bead399c3c9e52b'}, 'ROOT_Source102_catalog013_CS096211_corrected004_promotion_workflow_001.py': {'consumer': ('ROOT_Source102_catalog013_CS096211_corrected004_promotion_workflow_001.py', '8eff456fbfc6647f46d114e39d6e488e951668649bf1279c6cf66ad7aa192361'), 'workflow': ('ROOT_Source102_catalog013_CS096211_corrected004_promotion_workflow_001.py', '8eff456fbfc6647f46d114e39d6e488e951668649bf1279c6cf66ad7aa192361'), 'checkpoint_type': 'qcsd-ROOT-Source102-C13-CS096211-corrected004-two-proof-subset-promotion-completed-checkpoint-v1', 'transfer_type': 'qcsd-ROOT-Source102-C13-CS096211-corrected004-two-proof-subset-promotion-closed-checkpoint-transfer-v1', 'graph': '0911d3f1cdbfbd56c3596a76e47f61fe5591d5e8caa07e7c51b53fc8afa78905', 'contract': 'b762657c74120761955bc66edce5fdd4dff8fa507f5973203bead399c3c9e52b'}, 'ROOT_Source095_current094_latest_parent_retained_healthy82_checkpoint_consumer_010.py': {'consumer': ('ROOT_Source095_current094_latest_parent_retained_healthy82_checkpoint_consumer_010.py', '920581bb9388f3465e9bd54f50bc03f271a55b7d5ff3155d97f8e2df5b50b67f'), 'workflow': ('ROOT_Source095_current094_latest_parent_retained_healthy82_new_only_workflow_010.py', 'a42a7404b4d1d844a33ddc64e0761b787a395f2de19c1efd77572e77c8699c63'), 'checkpoint_type': 'qcsd-Source095-public094-completed-with-explicit-deferred-checkpoint-v1', 'transfer_type': 'qcsd-Source095-public094-explicit-deferred-checkpoint-transfer-v1', 'graph': '0911d3f1cdbfbd56c3596a76e47f61fe5591d5e8caa07e7c51b53fc8afa78905', 'contract': 'b762657c74120761955bc66edce5fdd4dff8fa507f5973203bead399c3c9e52b'}, 'ROOT_Source109_catalog_existing_members_checkpoint_consumer_020.py': {'consumer': ('ROOT_Source109_catalog_existing_members_checkpoint_consumer_020.py', 'ea1a927f03aec19a26ce257a0b0d81b451defdd7e095baa5112a3663748a4736'), 'workflow': ('ROOT_Source109_catalog_existing_members_new_only_workflow_020.py', '0d8a764d9ff1422be2ec667b4e806f64e16812b72b87cfa2c2a5620786225105'), 'checkpoint_type': 'qcsd-ROOT-Source101-catalog-multiwriter-completed-checkpoint-v1', 'transfer_type': 'qcsd-ROOT-Source101-catalog-closed-completed-checkpoint-transfer-v1', 'graph': '0911d3f1cdbfbd56c3596a76e47f61fe5591d5e8caa07e7c51b53fc8afa78905', 'contract': 'b762657c74120761955bc66edce5fdd4dff8fa507f5973203bead399c3c9e52b'}, 'ROOT_Source095_current094_latest_parent_retained_healthy82_checkpoint_consumer_011.py': {'consumer': ('ROOT_Source095_current094_latest_parent_retained_healthy82_checkpoint_consumer_011.py', 'f723f7acea29c0c5396a662d095ffdddaea5e0824ab4a1d2446704105ade01b9'), 'workflow': ('ROOT_Source095_current094_latest_parent_retained_healthy82_new_only_workflow_011.py', '9dd8b36d5504e80c74376e62053cb076e25b49b5a3da6567ec23e46e7e76232a'), 'checkpoint_type': 'qcsd-Source095-public094-completed-with-explicit-deferred-checkpoint-v1', 'transfer_type': 'qcsd-Source095-public094-explicit-deferred-checkpoint-transfer-v1', 'graph': '0911d3f1cdbfbd56c3596a76e47f61fe5591d5e8caa07e7c51b53fc8afa78905', 'contract': 'b762657c74120761955bc66edce5fdd4dff8fa507f5973203bead399c3c9e52b'}, 'ROOT_Source109_catalog_existing_members_checkpoint_consumer_022.py': {'consumer': ('ROOT_Source109_catalog_existing_members_checkpoint_consumer_022.py', 'cbac64fd66b18612e867d5de0d0892dec603f968d7ee7579bd364cc902259e2f'), 'workflow': ('ROOT_Source109_catalog_existing_members_new_only_workflow_022.py', 'aced14042302408da59a51a4ef7c9af2353639f6a2affab7031721e0f841a94b'), 'checkpoint_type': 'qcsd-ROOT-Source101-catalog-multiwriter-completed-checkpoint-v1', 'transfer_type': 'qcsd-ROOT-Source101-catalog-closed-completed-checkpoint-transfer-v1', 'graph': '0911d3f1cdbfbd56c3596a76e47f61fe5591d5e8caa07e7c51b53fc8afa78905', 'contract': 'b762657c74120761955bc66edce5fdd4dff8fa507f5973203bead399c3c9e52b'}, 'ROOT_Source109_catalog_existing_members_checkpoint_consumer_023.py': {'consumer': ('ROOT_Source109_catalog_existing_members_checkpoint_consumer_023.py', '11afa66855dddb1b6adf3a2e893469a28d309c5e4e5b6d2e4a8c042bedb0370f'), 'workflow': ('ROOT_Source109_catalog_existing_members_new_only_workflow_023.py', 'bdec8bc178b84b28b173ecad2c5a40d2af2a8d14e5742d10237436759eb0c6b4'), 'checkpoint_type': 'qcsd-ROOT-Source101-catalog-multiwriter-completed-checkpoint-v1', 'transfer_type': 'qcsd-ROOT-Source101-catalog-closed-completed-checkpoint-transfer-v1', 'graph': '0911d3f1cdbfbd56c3596a76e47f61fe5591d5e8caa07e7c51b53fc8afa78905', 'contract': 'b762657c74120761955bc66edce5fdd4dff8fa507f5973203bead399c3c9e52b'}, 'ROOT_Source107_Native137_Ang_CS180_public_checkpoint_consumer_004.py': {'consumer': ('ROOT_Source107_Native137_Ang_CS180_public_checkpoint_consumer_004.py', 'debcd53a3487897e51a4a74e372b70c8819d139a2109309960ef4be3f01af861'), 'workflow': ('ROOT_Source107_Native137_Ang_CS180_public_new_only_workflow_004.py', 'c1ca12f93d7b10ce7b3077022ad2e8aabeb9749f7c0edb5d6fdef1616e515f08'), 'checkpoint_type': 'qcsd-ROOT-Source107-Native137-Ang-CS180-public-completed-checkpoint-v1', 'transfer_type': 'qcsd-ROOT-Source107-Native137-Ang-CS180-public-closed-checkpoint-transfer-v1', 'graph': '84e449d927d78e77272d9830222cd4bfdaf913a2e8d4df3be537db11a831d9e7', 'contract': '427f0d8a3de8d6df029037a3e97c2132c42882b6196ed3aec317f521af1d1adf'}, 'ROOT_Source109_catalog_existing_members_checkpoint_consumer_024.py': {'consumer': ('ROOT_Source109_catalog_existing_members_checkpoint_consumer_024.py', 'e5b6c49ed259ad27857ccf45505d598efd2412dbdb96b1a9601f0cd54a8fcaa2'), 'workflow': ('ROOT_Source109_catalog_existing_members_new_only_workflow_024.py', 'eebe84b3280f7b6bc15eef5f6a3aceac67fd08e1476601fd0f862ae02ecbab37'), 'checkpoint_type': 'qcsd-ROOT-Source101-catalog-multiwriter-completed-checkpoint-v1', 'transfer_type': 'qcsd-ROOT-Source101-catalog-closed-completed-checkpoint-transfer-v1', 'graph': '0911d3f1cdbfbd56c3596a76e47f61fe5591d5e8caa07e7c51b53fc8afa78905', 'contract': 'b762657c74120761955bc66edce5fdd4dff8fa507f5973203bead399c3c9e52b'}, 'ROOT_Source095_current094_retained_Native126_four_missing_pilot_checkpoint_consumer_001.py': {'consumer': ('ROOT_Source095_current094_retained_Native126_four_missing_pilot_checkpoint_consumer_001.py', '8229dc9fa60d51cd3e2902758d2b529c4d5f2d976084e44e898497e4a8d533f3'), 'workflow': ('ROOT_Source095_current094_retained_Native126_four_missing_pilot_new_only_workflow_001.py', 'e412bd29773c1705724457fcd4de4d395f29671920cba1773ad70f0af046759f'), 'checkpoint_type': 'qcsd-Source095-public094-completed-with-explicit-deferred-checkpoint-v1', 'transfer_type': 'qcsd-Source095-public094-explicit-deferred-checkpoint-transfer-v1', 'graph': '0911d3f1cdbfbd56c3596a76e47f61fe5591d5e8caa07e7c51b53fc8afa78905', 'contract': 'b762657c74120761955bc66edce5fdd4dff8fa507f5973203bead399c3c9e52b'}, 'ROOT_Source109_catalog_existing_members_checkpoint_consumer_025.py': {'consumer': ('ROOT_Source109_catalog_existing_members_checkpoint_consumer_025.py', 'a70aad199269a6742d8aebe315ac01c3d1b8c46b436c71d8f76445e229a09baa'), 'workflow': ('ROOT_Source109_catalog_existing_members_new_only_workflow_025.py', '34968ee684575447d82f23b2fab060162bbaf55bf6073a1d13cb5d613a3b903a'), 'checkpoint_type': 'qcsd-ROOT-Source101-catalog-multiwriter-completed-checkpoint-v1', 'transfer_type': 'qcsd-ROOT-Source101-catalog-closed-completed-checkpoint-transfer-v1', 'graph': '0911d3f1cdbfbd56c3596a76e47f61fe5591d5e8caa07e7c51b53fc8afa78905', 'contract': 'b762657c74120761955bc66edce5fdd4dff8fa507f5973203bead399c3c9e52b'}, 'ROOT_Source109_BF1969_current_capture_two_proof_subset_publication_001.py': {'consumer': ('ROOT_Source109_BF1969_current_capture_two_proof_subset_publication_001.py', '10c2400d8ddc4d288ae0a095f349d12559c0f9051c913946adbf9d4d774181e1'), 'workflow': ('ROOT_Source109_BF1969_current_capture_two_proof_subset_publication_001.py', '10c2400d8ddc4d288ae0a095f349d12559c0f9051c913946adbf9d4d774181e1'), 'checkpoint_type': 'qcsd-ROOT-Source109-BF1969-current-capture-two-proof-subset-completed-checkpoint-v1', 'transfer_type': 'qcsd-ROOT-Source109-BF1969-current-capture-two-proof-subset-closed-checkpoint-transfer-v1', 'graph': '0911d3f1cdbfbd56c3596a76e47f61fe5591d5e8caa07e7c51b53fc8afa78905', 'contract': 'b762657c74120761955bc66edce5fdd4dff8fa507f5973203bead399c3c9e52b'}, 'ROOT_Source109_closed2000_cumulative_original_CS004_BF4292_publication_002.py': {'consumer': ('ROOT_Source109_closed2000_cumulative_original_CS004_BF4292_publication_002.py', '01d9bcb7dcaed04d21248d92d85a4932a90563185293a9e11454536992734db2'), 'workflow': ('ROOT_Source109_closed2000_cumulative_original_CS004_BF4292_publication_002.py', '01d9bcb7dcaed04d21248d92d85a4932a90563185293a9e11454536992734db2'), 'checkpoint_type': 'qcsd-ROOT-Source109-closed2000-cumulative-original-CS004-BF4292-subsets-completed-checkpoint-v1', 'transfer_type': 'qcsd-ROOT-Source109-closed2000-cumulative-original-CS004-BF4292-subsets-closed-checkpoint-transfer-v1', 'graph': '0911d3f1cdbfbd56c3596a76e47f61fe5591d5e8caa07e7c51b53fc8afa78905', 'contract': 'b762657c74120761955bc66edce5fdd4dff8fa507f5973203bead399c3c9e52b'}, 'ROOT_Source109_closed2000_cumulative_original_and_crossRTT_subset_publication_003.py': {'consumer': ('ROOT_Source109_closed2000_cumulative_original_and_crossRTT_subset_publication_003.py', '6c8022056ad194acf4ef3d86ea2f50e155a34fe61cd7920463cb9db15c4f0bfb'), 'workflow': ('ROOT_Source109_closed2000_cumulative_original_and_crossRTT_subset_publication_003.py', '6c8022056ad194acf4ef3d86ea2f50e155a34fe61cd7920463cb9db15c4f0bfb'), 'checkpoint_type': 'qcsd-ROOT-Source109-closed2000-cumulative-original-and-crossRTT-subsets-completed-checkpoint-v1', 'transfer_type': 'qcsd-ROOT-Source109-closed2000-cumulative-original-and-crossRTT-subsets-closed-checkpoint-transfer-v1', 'graph': '0911d3f1cdbfbd56c3596a76e47f61fe5591d5e8caa07e7c51b53fc8afa78905', 'contract': 'b762657c74120761955bc66edce5fdd4dff8fa507f5973203bead399c3c9e52b'}, 'ROOT_Source109_closed2000_known_stopped_cumulative_subset_publication_004.py': {'consumer': ('ROOT_Source109_closed2000_known_stopped_cumulative_subset_publication_004.py', '85573754efbd17ee9712cbbf9e0899dee9bbc10a59d4e814b188235445d6b2eb'), 'workflow': ('ROOT_Source109_closed2000_known_stopped_cumulative_subset_publication_004.py', '85573754efbd17ee9712cbbf9e0899dee9bbc10a59d4e814b188235445d6b2eb'), 'checkpoint_type': 'qcsd-ROOT-Source109-closed2000-known-stopped-cumulative-subsets-completed-checkpoint-v1', 'transfer_type': 'qcsd-ROOT-Source109-closed2000-known-stopped-cumulative-subsets-closed-checkpoint-transfer-v1', 'graph': '0911d3f1cdbfbd56c3596a76e47f61fe5591d5e8caa07e7c51b53fc8afa78905', 'contract': 'b762657c74120761955bc66edce5fdd4dff8fa507f5973203bead399c3c9e52b'},
 'ROOT_Source109_snapshot82535_H003_closed_current_publication_004.py': {'consumer': ('ROOT_Source109_snapshot82535_H003_closed_current_publication_004.py', '0dd9ff3abc7e72767b760e979f21f6f18fce343eb9c8c434576607270e85b8f8'), 'workflow': ('ROOT_Source109_snapshot82535_H003_closed_current_publication_004.py', '0dd9ff3abc7e72767b760e979f21f6f18fce343eb9c8c434576607270e85b8f8'), 'checkpoint_type': 'qcsd-ROOT-current109-snapshot82535-H003-completed-current-checkpoint-v1', 'transfer_type': 'qcsd-ROOT-current109-snapshot82535-H003-closed-current-checkpoint-transfer-v1', 'graph': '0911d3f1cdbfbd56c3596a76e47f61fe5591d5e8caa07e7c51b53fc8afa78905', 'contract': 'b762657c74120761955bc66edce5fdd4dff8fa507f5973203bead399c3c9e52b'}}


def _c():
    from . import resource_study_cohorts
    return resource_study_cohorts


def _need(value, message):
    if not value:
        raise ValueError(message)


def _key(row):
    return row["root"], row["attempt_id"]


def _same(left, right):
    return _c()._same(left, right)


def _ordered(rows):
    return sorted(rows, key=lambda row: (row["hostname"], row["mode"], row["slot"], row["root"]))


def _read_exact(ref, *, limit=64 * 1024**2):
    _need(type(ref) is dict and set(ref) == {"path", "sha256", "bytes"}, "exact immutable semantic reference required")
    path = Path(ref["path"])
    _need(path.is_absolute() and path.resolve(strict=True) == path
          and not any(p.is_symlink() for p in (path, *path.parents)), "canonical semantic input file required")
    fields = ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
    stamp = lambda value: tuple(getattr(value, name) for name in fields)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as handle:
        before = os.fstat(handle.fileno())
        _need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
              and (before.st_uid, before.st_gid) == (os.getuid(), os.getgid())
              and stat.S_IMODE(before.st_mode) == 0o444 and type(ref["bytes"]) is int
              and before.st_size == ref["bytes"] <= limit, "immutable semantic input owner/mode/size differs")
        raw = handle.read(limit + 1)
        _need(len(raw) == before.st_size and stamp(before) == stamp(os.fstat(handle.fileno())) == stamp(path.lstat())
              and hashlib.sha256(raw).hexdigest() == ref["sha256"], "semantic input bytes or descriptor changed")
    return raw


def _source(pair):
    path = SETUP / pair[0]
    raw = _read_exact({"path": str(path), "sha256": pair[1], "bytes": path.stat().st_size}, limit=4 * 1024**2)
    value = ModuleType("semantic_original_" + path.stem)
    value.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), value.__dict__)
    return value


def _unpack(value):
    _need(type(value) is dict and value.get("codec") == "zlib-base64"
          and type(value.get("expanded_bytes")) is int and 0 <= value["expanded_bytes"] <= 512 * 1024**2,
          "original bounded lossless parent envelope required")
    compressed = base64.b64decode(value["payload"], validate=True)
    _need(len(compressed) == value["compressed_bytes"]
          and hashlib.sha256(compressed).hexdigest() == value["compressed_sha256"], "parent compressed bytes differ")
    decoder = zlib.decompressobj()
    raw = decoder.decompress(compressed, value["expanded_bytes"] + 1)
    _need(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
          and len(raw) == value["expanded_bytes"] and hashlib.sha256(raw).hexdigest() == value["expanded_sha256"],
          "parent expanded bytes differ")
    return json.loads(raw)


def _full_ref(member, root, row):
    c = _c()
    base = deepcopy(row) if "accepted_row_sha256" in row and "root" in row else c._row_ref(root, row)
    return {**base, "cohort_id": member["cohort_id"],
            "native": deepcopy(member["cell"]["definition"]["native"]),
            "verifier_sha256": c._epochs()._sha(member["verifier"])}


def _fixed():
    _need(type(FIXED_FILES) is list and len(FIXED_FILES) == 16
          and type(FIXED_ROWS) is list and len(FIXED_ROWS) == 3
          and {_key(row)[1] for row in FIXED_ROWS} == set(ATTEMPTS)
          and type(PARENT_SOURCES) is dict and PARENT_SOURCES, "unsealed exact R3 SOURCE registry")


def evidence(ref):
    """Authenticate the actual six refusals, two phases and closed pools.

    An input may point to faithful passive copies. All expected original paths,
    complete raw SHA/length and phase/pool references remain immutable.
    """
    _fixed()
    declaration = json.loads(_read_exact(ref, limit=1024**2))
    _need(type(declaration) is dict and set(declaration) == {"record_type", "schema_version", "files"}
          and declaration["record_type"] == EVIDENCE and type(declaration["schema_version"]) is int
          and declaration["schema_version"] == 1 and type(declaration["files"]) is dict
          and set(declaration["files"]) == {item["guest_path"] for item in FIXED_FILES}, "exact complete fixed proof input required")
    loaded = {}
    for item in FIXED_FILES:
        actual = declaration["files"][item["guest_path"]]
        _need(type(actual) is dict and actual.get("sha256") == item["sha256"] and actual.get("bytes") == item["bytes"],
              "saved proof identity cannot be substituted")
        loaded[item["guest_path"]] = (item, json.loads(_read_exact(actual, limit=2 * 1024**2)))
    phases = {value["phase"]: (item, value) for item, value in loaded.values()
              if value.get("record_type") == "qcsd-ROOT-Catalog013-CS096211-corrected-counter-proof-production-result-v3"}
    _need(set(phases) == {1, 2}, "two real corrected004 phase summaries required")
    rows = {_key(row): row for row in FIXED_ROWS}
    seen, pairs = set(), []
    for item, status in loaded.values():
        if status.get("status") != "scientific_refusal":
            continue
        phase, ordinal = status["phase"], status["ordinal"]
        _need(type(phase) is int and phase in (1, 2) and type(ordinal) is int and ordinal in ORDINALS
              and (phase, ordinal) not in seen and status["facts"] is None
              and status["error"] == {"type": "ValueError", "message": ERROR}
              and status["is_checkpoint"] is False and type(status["scientific_credit_added"]) is int
              and status["scientific_credit_added"] == 0, "only exact two-phase clock refusals can retire")
        request = status["request"]
        _need(request["attempt_id"] == ORDINALS[ordinal] and _key(request) in rows, "foreign semantic refusal identity")
        row = rows[_key(request)]
        for name in ("root", "attempt_id", "hostname", "mode", "slot", "five_tuple"):
            _need(_same(request[name], row[name]), "refusal request differs from full historical identity: " + name)
        _need(request["receipt"] == {"path": str(Path(row["root"]) / row["receipt_path"]), "sha256": row["receipt_sha256"]}
              and request["receipt_raw_sha256"] == row["receipt_sha256"], "refusal receipt bytes differ")
        authority = status["context"]["corrected_execution_worker"]["authority"]
        _need(authority["worker"]["sha256"] == WORKER and authority["execution_is_unmodified_worker002"] is False
              and authority["counter_correction"]["corrected_function_file_sha256"] == CORRECTION
              and authority["counter_correction"]["physical_10ms_guard_changed"] is False,
              "original strict corrected004 scientific reader required")
        phase_item, summary = phases[phase]
        _need(any(r == {"path": item["guest_path"], "sha256": item["sha256"], "bytes": item["bytes"]}
                  for r in summary["status_refs"]), "refusal absent from its real phase")
        closed_path = str(Path(item["guest_path"]).parent / "closed.json")
        closed_item, closed = loaded[closed_path]
        _need(closed["phase"] == phase and closed["pool_id"] == status["pool_id"]
              and closed["hard_failure"] is None and closed["all_started_original_workers_joined_before_record"] is True
              and closed["execution"]["all_started_workers_joined"] is True
              and any(r["path"] == closed_path and r["sha256"] == closed_item["sha256"] for r in summary["closed_pool_refs"])
              and any(r["path"] == item["guest_path"] and r["sha256"] == item["sha256"]
                      and r["bytes"] == item["bytes"] for r in closed["statuses"]), "genuine closed refusal pool required")
        seen.add((phase, ordinal))
        pairs.append({"phase": phase, "ordinal": ordinal, "status": deepcopy(item),
                      "closed_pool": deepcopy(closed_item), "phase_summary": deepcopy(phase_item)})
    _need(seen == {(phase, ordinal) for phase in (1, 2) for ordinal in ORDINALS}, "all six exact refusals required")
    return sorted(pairs, key=lambda row: (row["ordinal"], row["phase"]))


def _annotation(entry):
    value = entry["semantic_refusals"]
    fields = {"record_type", "schema_version", "journal", "retired"}
    _need(type(value) is dict and set(value) == fields and value["record_type"] == SCOPE
          and type(value["schema_version"]) is int and value["schema_version"] == 1, "typed exact semantic row scope required")
    expected = [row for row in FIXED_ROWS if (row["hostname"], row["mode"]) == (entry["hostname"], entry["mode"])]
    _need(expected and _same(value["retired"], expected), "semantic scope may classify only its exact fixed rows")
    journal = json.loads(_read_exact(value["journal"], limit=4 * 1024**2))
    _need(journal["record_type"] == JOURNAL and journal["change"] == CHANGE
          and _same(journal["retired"], FIXED_ROWS), "semantic journal authority differs")
    _need(_same(evidence(journal["evidence"]), journal["negative_proofs"]), "semantic journal lost original proof authority")
    return {_key(row): row for row in expected}


def member_sciences(entry):
    """Exact same-science retirement branch; no ordinary type is relaxed."""
    _need(type(entry) is dict and set(entry) == {"hostname", "mode", "science", "members", "writer", "semantic_refusals"},
          "semantic retirement cannot alias a condition/resource/budget stratum")
    _annotation(entry)
    return {member["cohort_id"]: entry["science"] for member in entry["members"]}


def _project(entry, histories, retired):
    """Full per-member history was authenticated before entering this reduction."""
    c = _c()
    active, seen_retired, tuples, slots, history_slots = [], set(), set(), set(), {}
    for member, store, row in histories:
        full = _full_ref(member, str(store.root), row)
        identity = _key(full)
        _need(type(row["slot"]) is int and 1 <= row["slot"] <= 400
              and c._json(c._tuple(c._load(row["five_tuple"]))).decode() == row["five_tuple"]
              and row["five_tuple"] not in tuples, "semantic history repeats or changes a historical tuple")
        tuples.add(row["five_tuple"])
        is_retired = identity in retired
        history_slots.setdefault(row["slot"], []).append(is_retired)
        if is_retired:
            _need(member["frozen_accepted"] is not None and _same(full, retired[identity])
                  and identity not in seen_retired, "retired historical row is not its exact frozen original")
            seen_retired.add(identity)
        else:
            _need(row["slot"] not in slots, "two active members repeat a shared slot")
            slots.add(row["slot"])
            active.append((member, store, row))
    _need(seen_retired == set(retired) and len(active) <= 400
          and all(len(flags) == 1 or len(flags) == 2 and sum(flags) == 1 for flags in history_slots.values()),
          "only exact retired-versus-replacement slot overlap is allowed")
    return active


def accepted(entry, *, self_store=None, connection=None):
    c = _c()
    retired = _annotation(entry)
    history = []
    for member in entry["members"]:
        root = member["cell"]["root"]
        store = self_store if self_store is not None and str(self_store.root) == root else c.StudyStore(root)
        own = connection if store is self_store else None
        key = entry["hostname"], entry["mode"]
        rows = c._rows(store, key, own)
        c._accepted_attempts(store, key, rows, own)
        local_slots, local_tuples = set(), set()
        for row in rows:
            _need(row["slot"] not in local_slots and row["five_tuple"] not in local_tuples, "member local slot/tuple repeats")
            local_slots.add(row["slot"]); local_tuples.add(row["five_tuple"])
        if member["frozen_accepted"] is not None:
            marker = c._epochs()._read(store.root / c.MARKER)
            parent = c.StudyStore(marker["parent"])
            _need(_same(marker, c._marker(store, parent)), "frozen semantic member parent differs")
            frozen = c._frozen_value(parent, member)
            _need(_same(frozen["rows"], [c._row_ref(root, row) for row in rows])
                  and not c._rows(store, key, own, active=True), "whole frozen semantic SQL history changed")
        history.extend((member, store, row) for row in rows)
    return _project(entry, history, retired)


def check_frozen(parent, entry):
    c = _c()
    retired = _annotation(entry)
    history = []
    for member in entry["members"]:
        if member["frozen_accepted"] is None:
            continue
        store = c.StudyStore(member["cell"]["root"])
        # Full original nine-field manifest parsing and row validation stays
        # in the original function, before any retired classification.
        for row in c._frozen_value(parent, member)["rows"]:
            history.append((member, store, row))
    _project(entry, history, retired)


def _historical_rows(registry):
    c = _c()
    result = []
    for entry in registry:
        _need("semantic_refusals" not in entry, "the exact R3 admission cannot be repeated")
        # The original unfiltered reader authenticates every SQL/attempt and
        # frozen-row binding. No scientific negative is filtered here.
        result.extend(_full_ref(member, str(store.root), row) for member, store, row in c._accepted(entry))
    return _ordered(result)


def _parent(ref, records):
    """Original Guest standard authority plus the exact actual prefix.

    The ROOT owner must separately authenticate the actual standard17 normal
    before uploading this genuine transfer. This Guest predicate is the same
    independent DTO/source predicate used by existing public observers.
    """
    c = _c()
    value = json.loads(_read_exact(ref))
    name = Path(value["controller"]["path"]).name
    spec = PARENT_SOURCES.get(name)
    _need(spec is not None and value["controller"] == {"path": str(HOST_SETUP / name), "sha256": spec["consumer"][1]}
          and value["completed_checkpoint"]["workflow_controller"] == {"path": str(HOST_SETUP / spec["workflow"][0]), "sha256": spec["workflow"][1]},
          "exact separately supported current standard parent required")
    class Files:
        def read(self, path, digest=None, *, limit=4 * 1024**2, **unused):
            target = Path(path)
            _need(target.parent == SETUP, "parent authority may read only fixed Guest setup sources")
            return _read_exact({"path": str(target), "sha256": digest, "bytes": target.stat().st_size}, limit=limit)
        def reference(self, source, **kwargs):
            return self.read(source["path"], source["sha256"], **kwargs)
    files = Files()
    authority, partition = _source(AUTHORITY), _source(PARTITION)
    state = authority.guest_prior(value, files,
        {"path": str(SETUP / name), "sha256": spec["consumer"][1]}, partition, _unpack,
        source=spec["consumer"], workflow=spec["workflow"], transfer_type=spec["transfer_type"],
        cp_types=(spec["checkpoint_type"],), graph=spec["graph"], contract=spec["contract"])
    _need(_same(state["records"], records), "retirement standard parent does not cover the exact current admission prefix")
    cp = value["completed_checkpoint"]
    qualified = partition.checked_partition(cp["deferred_partition"], state)
    pending = {_key(row): row for row in cp["deferred_partition"]["deferred_accepted"]}
    _need(not {_key(row) for row in FIXED_ROWS} & {_key(row) for row in qualified}
          and all(_key(row) in pending and _same(row, pending[_key(row)]) for row in FIXED_ROWS),
          "only exact currently unqualified pending rows may retire")
    return state, cp["deferred_partition"]


def _new_material(parent, new, records):
    c = _c(); e = c._epochs()
    _need(records and records[-1]["record_type"] == c.ADMISSION, "retirement requires real current runtime-cohort authority")
    _need(not any("semantic_refusals" in entry for entry in records[-1]["cohorts"]), "R3 transition is single-use")
    context, context_sha = c._input_context(new.root, new.plan())
    _need(_same(context["parent"], {"root": str(parent.root), "study_sha256": parent._file("study.json")[1]["sha256"]})
          and _same(context["predecessor"], records[-1]) and context["predecessor_sha256"] == e._sha(records[-1])
          and "cs180_condition" not in context, "fresh genuine same-Native preparation context must bind the actual head")
    previous_roots = {cell["root"] for record in records for cell in record["cells"]}
    _need(str(new.root) not in previous_roots and not (new.root / c.MARKER).exists()
          and not (new.root / c.MARKER).is_symlink(), "retirement needs a genuinely unclaimed fresh writer")
    with new._transaction() as connection:
        _need(not connection.execute("SELECT 1 FROM attempts").fetchone()
              and not connection.execute("SELECT 1 FROM accepted").fetchone(), "fresh writer cannot import evidence")
    from .resource_study_lineage import no_retired_history
    no_retired_history(new)
    _need(any(c._same(e._plan(new), c.StudyStore(root).plan()) for root in previous_roots), "retirement plan/class map changed")
    old_cells = {e._key(cell): cell for cell in records[-1]["cells"]}
    affected = []
    for key in CELLS:
        e._verify_preparation(new, key[0])
        candidate = e._cell(new, *key)
        old = old_cells[key]
        entry = c._entry(records[-1]["cohorts"], key)
        _need(not set(entry) & {"resource_versions", "condition_strata", "science_strata", "semantic_refusals"}
              and candidate["definition"]["ready"] is True
              and _same(candidate["definition"]["native"], old["definition"]["native"])
              and _same(c._science(candidate, records[-1]["class_transition"]), entry["science"]),
              "R3 exception preserves exact same Native, ordered20 and all scientific settings")
        _need(c._writer(entry)["cell"] == old and old["root"] == FIXED_ROWS[0]["root"], "retirement old writer differs")
        affected.append({"hostname": key[0], "mode": key[1], "previous_definition_sha256": old["definition_sha256"],
                         "new_definition_sha256": candidate["definition_sha256"]})
    return context_sha, affected


def _declaration(parent, new, records, evidence_ref, parent_ref, rationale):
    c = _c(); e = c._epochs()
    _need(type(rationale) is str and rationale.strip(), "explicit scoped semantic rationale required")
    context_sha, affected = _new_material(parent, new, records)
    proofs = evidence(evidence_ref)
    state, partition = _parent(parent_ref, records)
    historical = _historical_rows(records[-1]["cohorts"])
    _need(_same(historical, _ordered(state["composition"]["accepted"])), "current whole accepted SQL differs from genuine standard parent")
    current = {_key(row): row for row in historical}
    _need(all(_key(row) in current and _same(current[_key(row)], row) for row in FIXED_ROWS), "actual three historical rows changed")
    return {"record_type": DECLARATION, "schema_version": 1, "change": CHANGE,
        "parent_study_sha256": parent._file("study.json")[1]["sha256"], "predecessor_admission_sha256": e._sha(records[-1]),
        "selected_hostnames": records[-1]["class_transition"]["class_selection"]["selected_hostnames"],
        "affected": affected, "fresh_root": str(new.root), "input_context_sha256": context_sha,
        "retired": deepcopy(FIXED_ROWS), "evidence": deepcopy(evidence_ref), "negative_proofs": proofs,
        "current_standard_parent": deepcopy(parent_ref), "qualified_inventory_sha256": partition["qualified_accepted_inventory_sha256"],
        "retained_historical_inventory_sha256": e._sha(historical), "verifier": c.verifier_contract(),
        "rationale": rationale, "scientific_credit_added": 0, "same_native_exception_only_exact_three": True}


def template(parent, cohort_root, *, evidence_path, evidence_sha256, parent_transfer_path, parent_transfer_sha256, rationale):
    c = _c(); e = c._epochs()
    parent, new = c.StudyStore(Path(parent).absolute()), c.StudyStore(Path(cohort_root).absolute())
    def ref(path, digest):
        p = e._regular(Path(path).absolute())
        return {"path": str(p), "sha256": digest, "bytes": p.stat().st_size}
    with e._lock(parent.root):
        records = e._records(parent)
        return _declaration(parent, new, records, ref(evidence_path, evidence_sha256),
                            ref(parent_transfer_path, parent_transfer_sha256), rationale)


def _journal(declaration):
    return {"record_type": JOURNAL, "schema_version": 1, "change": CHANGE,
        "parent_study_sha256": declaration["parent_study_sha256"],
        "predecessor_admission_sha256": declaration["predecessor_admission_sha256"],
        "fresh_root": declaration["fresh_root"], "retired": deepcopy(FIXED_ROWS),
        "evidence": deepcopy(declaration["evidence"]), "negative_proofs": deepcopy(declaration["negative_proofs"]),
        "current_standard_parent": deepcopy(declaration["current_standard_parent"]),
        "qualified_inventory_sha256": declaration["qualified_inventory_sha256"],
        "retained_historical_inventory_sha256": declaration["retained_historical_inventory_sha256"],
        "scientific_credit_added": 0, "old_SQL_rows_changed": False}


def _exclusion(key, journal_ref):
    c = _c()
    return {"record_type": EXCLUSION, "schema_version": 1, "cell": list(key), "scientific_credit": False,
        "journal": journal_ref, "receipts": [{**deepcopy(row), "five_tuple": c._load(row["five_tuple"])}
            for row in FIXED_ROWS if (row["hostname"], row["mode"]) == key]}


def create(parent, cohort_root, declaration_path, declaration_sha256):
    """Publish one head under original locks; never mutate old accepted SQL."""
    c = _c(); e = c._epochs()
    from .resource_study_lineage import prepare_fences, publication_scope, validate_cells
    parent, new = c.StudyStore(Path(parent).absolute()), c.StudyStore(Path(cohort_root).absolute())
    path = e._regular(Path(declaration_path).absolute())
    declaration = e._read(path)
    _need(c.sha256_file(path) == declaration_sha256 == e._sha(declaration), "exact immutable semantic declaration required")
    with e.docker_lock(), e._lock(parent.root):
        records = e._records(parent)
        expected = _declaration(parent, new, records, declaration["evidence"], declaration["current_standard_parent"], declaration["rationale"])
        _need(_same(declaration, expected), "semantic declaration or real parent/preparation changed")
        roots = {cell["root"] for record in records for cell in record["cells"]} | {str(new.root)}
        e._idle([c.StudyStore(root) for root in sorted(roots)])
        journal = _journal(declaration)
        journal_raw = c.canonical_json(journal)
        relative = "semantic-refusals/" + e._sha(journal) + ".json"
        c._create(parent.root / relative, journal_raw)
        journal_ref = {"path": str(parent.root / relative), "sha256": e._sha(journal), "bytes": len(journal_raw)}
        registry = deepcopy(records[-1]["cohorts"])
        cells = {e._key(cell): cell for cell in records[-1]["cells"]}
        for key in CELLS:
            entry = c._entry(registry, key); previous = c._writer(entry)
            old_store = c.StudyStore(previous["cell"]["root"])
            frozen = {"record_type": c.SNAPSHOT, "cohort_id": previous["cohort_id"],
                "rows": [c._row_ref(str(old_store.root), row) for row in c._rows(old_store, key)],
                "authority": "existing-accepted-SQL-rows; no new raw qualification"}
            relative = "runtime-cohorts/" + e._sha(frozen) + ".json"
            c._create(parent.root / relative, c.canonical_json(frozen))
            previous["frozen_accepted"] = {"path": relative, "sha256": e._sha(frozen)}
            candidate = e._cell(new, *key); member = c._member(candidate, declaration["verifier"])
            entry["members"].append(member); entry["writer"] = member["cohort_id"]
            entry["semantic_refusals"] = {"record_type": SCOPE, "schema_version": 1,
                "journal": journal_ref, "retired": [deepcopy(row) for row in FIXED_ROWS if (row["hostname"], row["mode"]) == key]}
            cells[key] = candidate
        exclusions = deepcopy(records[-1]["exclusions"])
        for key in CELLS:
            value = _exclusion(key, journal_ref)
            relative = "epoch-exclusions/" + e._sha(value) + ".json"
            c._create(parent.root / relative, c.canonical_json(value))
            exclusions.append({"cell": list(key), "path": relative, "sha256": e._sha(value)})
        validate_cells([member["cell"] for entry in registry for member in entry["members"]], records[-1]["class_transition"])
        e._bind(new, parent)
        fences = prepare_fences(parent, records, cells, records[-1]["class_transition"])
        markers = dict(records[-1].get("cohort_memberships", {}))
        for root in sorted({m["cell"]["root"] for entry in registry for m in entry["members"]}):
            store = c.StudyStore(root); value = c._marker(store, parent)
            if root not in markers:
                _need(not (store.root / c.MARKER).exists() and not (store.root / c.MARKER).is_symlink(),
                      "orphaned semantic membership requires explicit recovery")
                c._create(store.root / c.MARKER, c.canonical_json(value))
            markers[root] = e._sha(value)
        value = {"record_type": c.ADMISSION, "sequence": len(records), "previous_sha256": e._sha(records[-1]),
            "parent_study_sha256": parent._file("study.json")[1]["sha256"], "change": CHANGE,
            "affected": [list(key) for key in CELLS], "cells": [cells[key] for key in sorted(cells)],
            "exclusions": exclusions, "class_transition": deepcopy(records[-1]["class_transition"]),
            "write_fences": fences, "cohorts": sorted(registry, key=lambda row: (row["hostname"], row["mode"])),
            "cohort_memberships": markers, "compatibility_declaration": {"path": str(path), "sha256": declaration_sha256}}
        validate_record(parent, records, value, declaration["verifier"])
        _need(c.sha256_file(path) == declaration_sha256 and _same(declaration["verifier"], c.verifier_contract()),
              "semantic declaration or current qualifying source changed before publication")
        # Recheck all fixed evidence and live pre-head inputs before the sole
        # authority switch; no marker/journal alone makes a retired row inactive.
        _need(_same(evidence(declaration["evidence"]), declaration["negative_proofs"]), "proof input changed before semantic head CAS")
        e._idle([c.StudyStore(root) for root in sorted(roots)])
        c._create(parent.root / "epoch-admissions" / f"{len(records):06d}.json", c.canonical_json(value))
        with publication_scope(parent, records, value), parent._transaction() as connection:
            before = c.canonical_json({"sequence": len(records)-1, "sha256": e._sha(records[-1])}).decode()
            current = connection.execute("SELECT value FROM meta WHERE key='epoch_head'").fetchone()
            _need(current is not None and current[0] == before, "semantic parent head changed before publication")
            connection.execute("UPDATE meta SET value=? WHERE key='epoch_head'",
                (c.canonical_json({"sequence": len(records), "sha256": e._sha(value)}).decode(),))
        return value


def validate_record(parent, records, value, contract):
    """Independent typed history reader; no new row is trusted by its label."""
    c = _c(); e = c._epochs()
    fields = {"record_type", "sequence", "previous_sha256", "parent_study_sha256", "change", "affected", "cells",
        "exclusions", "class_transition", "write_fences", "cohorts", "cohort_memberships", "compatibility_declaration"}
    prior = records[-1]
    _need(type(value) is dict and set(value) == fields and value["record_type"] == c.ADMISSION
          and type(value["sequence"]) is int and value["sequence"] == len(records)
          and value["previous_sha256"] == e._sha(prior) and value["change"] == CHANGE
          and value["parent_study_sha256"] == parent._file("study.json")[1]["sha256"]
          and _same(value["class_transition"], prior["class_transition"])
          and value["affected"] == [list(key) for key in CELLS], "semantic admission prefix/class map/type differs")
    ref = value["compatibility_declaration"]
    _need(type(ref) is dict and set(ref) == {"path", "sha256"}, "exact semantic declaration reference required")
    path = e._regular(Path(ref["path"]))
    declaration = e._read(path)
    expected_fields = {"record_type", "schema_version", "change", "parent_study_sha256", "predecessor_admission_sha256",
        "selected_hostnames", "affected", "fresh_root", "input_context_sha256", "retired", "evidence", "negative_proofs",
        "current_standard_parent", "qualified_inventory_sha256", "retained_historical_inventory_sha256", "verifier",
        "rationale", "scientific_credit_added", "same_native_exception_only_exact_three"}
    _need(c.sha256_file(path) == ref["sha256"] == e._sha(declaration)
          and type(declaration) is dict and set(declaration) == expected_fields
          and declaration["record_type"] == DECLARATION and type(declaration["schema_version"]) is int
          and declaration["schema_version"] == 1 and declaration["change"] == CHANGE
          and declaration["parent_study_sha256"] == value["parent_study_sha256"]
          and declaration["predecessor_admission_sha256"] == e._sha(prior)
          and declaration["selected_hostnames"] == value["class_transition"]["class_selection"]["selected_hostnames"]
          and _same(declaration["retired"], FIXED_ROWS) and _same(declaration["verifier"], contract)
          and declaration["same_native_exception_only_exact_three"] is True
          and type(declaration["scientific_credit_added"]) is int and declaration["scientific_credit_added"] == 0
          and type(declaration["rationale"]) is str and declaration["rationale"].strip(), "semantic declaration changed")
    _need(_same(evidence(declaration["evidence"]), declaration["negative_proofs"]), "six original negative proof joins changed")
    state, partition = _parent(declaration["current_standard_parent"], records)
    _need(declaration["qualified_inventory_sha256"] == partition["qualified_accepted_inventory_sha256"]
          and declaration["retained_historical_inventory_sha256"] == e._sha(_ordered(state["composition"]["accepted"])),
          "semantic declaration changed original qualified or historical inventory")
    old_entries = {(entry["hostname"], entry["mode"]): entry for entry in prior["cohorts"]}
    entries = {(entry["hostname"], entry["mode"]): entry for entry in value["cohorts"]}
    old_cells = {e._key(cell): cell for cell in prior["cells"]}
    cells = {e._key(cell): cell for cell in value["cells"]}
    _need(len(entries) == len(value["cohorts"]) and entries.keys() == old_entries.keys()
          and len(cells) == len(value["cells"]) and cells.keys() == old_cells.keys()
          and not any("semantic_refusals" in entry for entry in old_entries.values()), "semantic admission changes logical membership")
    roots = {cell["root"] for record in records for cell in record["cells"]}
    _need(declaration["fresh_root"] not in roots
          and {cells[key]["root"] for key in CELLS} == {declaration["fresh_root"]}, "semantic replacement root is not genuinely new")
    journal_ref = None
    affected = []
    for key, entry in entries.items():
        old = old_entries[key]
        if key not in CELLS:
            _need(_same(entry, old) and _same(cells[key], old_cells[key]), "semantic admission changed an unaffected cell")
            continue
        _need(set(old) == {"hostname", "mode", "science", "members", "writer"}
              and set(entry) == set(old) | {"semantic_refusals"}
              and _same(entry["science"], old["science"])
              and len(entry["members"]) == len(old["members"]) + 1, "semantic admission changes scientific ancestry")
        for before, after in zip(old["members"], entry["members"][:-1]):
            expected = deepcopy(after)
            if before["cohort_id"] == old["writer"]:
                _need(after["frozen_accepted"] is not None, "whole previous writer was not frozen")
                expected["frozen_accepted"] = None
            _need(_same(before, expected), "semantic admission rewrote an old member")
        member = c._writer(entry); candidate = cells[key]
        _need(entry["members"][-1] is member and _same(member, c._member(candidate, contract))
              and candidate["definition"]["ready"] is True
              and _same(candidate["definition"]["native"], old_cells[key]["definition"]["native"])
              and _same(c._science(candidate, value["class_transition"]), old["science"]),
              "semantic admission did not preserve genuine same-Native ready scientific definition")
        annotation = entry["semantic_refusals"]
        _annotation(entry)
        if journal_ref is None:
            journal_ref = annotation["journal"]
        _need(_same(annotation["journal"], journal_ref)
              and _same(json.loads(_read_exact(journal_ref, limit=4 * 1024**2)), _journal(declaration)),
              "both affected cells must bind the same actual immutable journal")
        affected.append({"hostname": key[0], "mode": key[1], "previous_definition_sha256": old_cells[key]["definition_sha256"],
                         "new_definition_sha256": candidate["definition_sha256"]})
    _need(_same(declaration["affected"], sorted(affected, key=lambda row: (row["hostname"], row["mode"])))
          and len(value["exclusions"]) == len(prior["exclusions"]) + len(CELLS)
          and _same(value["exclusions"][:-len(CELLS)], prior["exclusions"]), "semantic declared scope or old exclusions changed")
    for key, exclusion_ref in zip(CELLS, value["exclusions"][-len(CELLS):]):
        expected = _exclusion(key, journal_ref)
        _need(type(exclusion_ref) is dict and set(exclusion_ref) == {"cell", "path", "sha256"}
              and exclusion_ref["cell"] == list(key) and exclusion_ref["path"].startswith("epoch-exclusions/")
              and _same(e._read(parent._relative(exclusion_ref["path"])), expected)
              and exclusion_ref["sha256"] == e._sha(expected)
              and c.sha256_file(parent._relative(exclusion_ref["path"])) == exclusion_ref["sha256"],
              "all exact old tuples must remain in immutable exclusions")
    new = c.StudyStore(declaration["fresh_root"])
    context, context_sha = c._input_context(new.root, new.plan())
    _need(context_sha == declaration["input_context_sha256"] and _same(context["predecessor"], prior),
          "semantic fresh preparation input head changed")
    c._validate_members(parent, value, cells, contract)


def status_projection(records, result):
    """Publish a new explicit active/history type; old composition stays whole."""
    c = _c(); e = c._epochs()
    annotated = [entry for entry in records[-1]["cohorts"] if "semantic_refusals" in entry]
    if not annotated:
        return result
    _need({(entry["hostname"], entry["mode"]) for entry in annotated} == set(CELLS), "partial semantic scope in current metadata")
    retired = []
    for entry in annotated:
        retired.extend(_annotation(entry).values())
    _need(_same(_ordered(retired), _ordered(FIXED_ROWS)), "current semantic history lost an exact retired row")
    active = result["accepted"]
    _need(not {_key(row) for row in active} & {_key(row) for row in retired}, "retired history is counted as active")
    historical = _ordered([*active, *retired])
    result = deepcopy(result)
    result.update(record_type=COMPOSITION, schema_version=2,
        historical_accepted=historical, historical_accepted_count=len(historical),
        retired_historical_accepted=_ordered(retired), retired_historical_accepted_count=len(retired),
        active_accepted_count=len(active), retired_inventory_sha256=e._sha(_ordered(retired)),
        historical_inventory_sha256=e._sha(historical), active_inventory_sha256=e._sha(_ordered(active)),
        semantic_retirement_change=CHANGE,
        target_count_policy="active rows count toward shared400; exact scientific refusals remain immutable SQL/raw history and permanent tuple exclusions")
    _need(result["historical_accepted_count"] == result["accepted_count"] + result["retired_historical_accepted_count"],
          "semantic raw-history/active conservation failed")
    by_key = {(entry["hostname"], entry["mode"]): entry for entry in annotated}
    for cell in result["cells"]:
        key = cell["hostname"], cell["mode"]
        if key in by_key:
            count = sum((row["hostname"], row["mode"]) == key for row in retired)
            cell.update(retired_historical_accepted=count, historical_accepted=cell["accepted"] + count,
                        active_accepted=cell["accepted"])
    return result


def checked_active_partition(value, state):
    """New Q/D/R type only; the old P587 full=Q+D contract stays unchanged.

    L denotes the target inventory represented by the previous composition,
    including these three immutable rows. It does not reclassify older,
    separately typed resource-version strata.
    """
    c = _c(); e = c._epochs()
    fields = {"record_type", "schema_version", "qualified_accepted", "deferred_accepted", "retired_accepted",
        "qualified_accepted_count", "deferred_accepted_count", "retired_accepted_count", "active_accepted_count",
        "full_local_accepted_count", "qualified_accepted_inventory_sha256", "deferred_accepted_inventory_sha256",
        "retired_accepted_inventory_sha256", "active_accepted_inventory_sha256", "full_local_accepted_inventory_sha256",
        "scientific_retirement_change", "retired_SQL_history_preserved", "old_tuples_permanently_excluded"}
    _need(type(value) is dict and set(value) == fields and value["record_type"] == PARTITION_TYPE
          and type(value["schema_version"]) is int and value["schema_version"] == 1
          and value["scientific_retirement_change"] == CHANGE
          and value["retired_SQL_history_preserved"] is True and value["old_tuples_permanently_excluded"] is True,
          "new explicit Q/D/R authority is required; old P587 cannot be relabelled")
    composition = state["composition"]
    _need(composition["record_type"] == COMPOSITION and composition["schema_version"] == 2,
          "Q/D/R requires the actual separately typed active/history composition")
    qualified, deferred, retired = (value[name] for name in ("qualified_accepted", "deferred_accepted", "retired_accepted"))
    for rows in (qualified, deferred, retired):
        _need(type(rows) is list and _same(rows, _ordered(rows)) and len({_key(row) for row in rows}) == len(rows),
              "Q/D/R inventory is not ordered or repeats an identity")
    q, d, r = ({_key(row): row for row in rows} for rows in (qualified, deferred, retired))
    _need(not q.keys() & d.keys() and not q.keys() & r.keys() and not d.keys() & r.keys()
          and _same(retired, _ordered(FIXED_ROWS)), "Q/D/R overlaps or changes the exact retired history")
    active = _ordered([*qualified, *deferred]); historical = _ordered([*active, *retired])
    _need(_same(active, _ordered(composition["accepted"]))
          and _same(retired, composition["retired_historical_accepted"])
          and _same(historical, composition["historical_accepted"]), "Q/D/R does not cover the complete current target inventory")
    inventories = {"qualified_accepted": qualified, "deferred_accepted": deferred, "retired_accepted": retired,
                   "active_accepted": active, "full_local_accepted": historical}
    for name, rows in inventories.items():
        _need(type(value[name + "_count"]) is int and value[name + "_count"] == len(rows)
              and value[name + "_inventory_sha256"] == e._sha(rows), "Q/D/R count or whole inventory digest differs")
    _need(all(type(composition[name]) is int for name in ("accepted_count", "active_accepted_count", "historical_accepted_count", "retired_historical_accepted_count"))
          and composition["accepted_count"] == len(active) == composition["active_accepted_count"]
          and composition["historical_accepted_count"] == len(historical)
          and composition["retired_historical_accepted_count"] == len(retired), "active/history metadata conservation differs")
    counts = {}
    for row in active:
        key = row["hostname"], row["mode"]
        counts[key] = counts.get(key, 0) + 1
        _need(counts[key] <= 400, "Q/D/R active inventory exceeds an original shared400 cell")
    return qualified


def partition_for_retirement(prior_partition, before, after):
    """Reclassify only the fixed three D rows; issue no new scientific credit."""
    c = _c(); e = c._epochs()
    old = _source(PARTITION)
    qualified = old.checked_partition(prior_partition, before)
    _need(len(after["records"]) == len(before["records"]) + 1
          and _same(after["records"][:-1], before["records"])
          and after["records"][-1]["change"] == CHANGE,
          "retirement partition needs exactly one authentic new semantic admission")
    historical = _ordered(before["composition"]["accepted"])
    retired = _ordered(FIXED_ROWS)
    pending = {_key(row): row for row in prior_partition["deferred_accepted"]}
    _need(not {_key(row) for row in qualified} & {_key(row) for row in retired}
          and all(_key(row) in pending and _same(pending[_key(row)], row) for row in retired),
          "only the exact currently pending rows may retire")
    deferred = _ordered([row for key, row in pending.items() if key not in {_key(row) for row in retired}])
    active = _ordered([*qualified, *deferred])
    _need(_same(after["composition"]["historical_accepted"], historical)
          and _same(_ordered(after["composition"]["accepted"]), active),
          "retirement changes another row or admits unproved replacement credit")
    value = {"record_type": PARTITION_TYPE, "schema_version": 1,
        "qualified_accepted": _ordered(qualified), "deferred_accepted": deferred, "retired_accepted": retired,
        "scientific_retirement_change": CHANGE, "retired_SQL_history_preserved": True,
        "old_tuples_permanently_excluded": True}
    for name, rows in (("qualified_accepted", value["qualified_accepted"]), ("deferred_accepted", deferred),
                       ("retired_accepted", retired), ("active_accepted", active), ("full_local_accepted", historical)):
        value[name + "_count"] = len(rows)
        value[name + "_inventory_sha256"] = e._sha(rows)
    checked_active_partition(value, after)
    return value


def carry_active_partition(partition, before, after, new_accepted, *, writer_root, cells, max_new_accepted):
    """Additional metadata predicate AFTER an original two-whole-proof body.

    This function neither executes science nor authorizes a pending promotion.
    A consumer must authenticate every new receipt twice before calling it.
    Later scientific refusals remain explicit pending rows until a separately
    authorized inventory and versioned transition exist.
    """
    c = _c(); e = c._epochs()
    checked_active_partition(partition, before)
    _need(_same(before["composition"]["class_selection"], after["composition"]["class_selection"]),
          "Q/D/R public carry changed the original50 class selection")
    roster = after["composition"]["class_selection"]["selected_hostnames"]
    _need(type(roster) is list and len(roster) == len(set(roster)) == 50
          and type(writer_root) is str and type(cells) is list and cells
          and all(type(cell) in (list, tuple) and len(cell) == 2 and cell[0] in roster
                  and cell[1] in ("undefended", "front", "tamaraw", "buflo", "cs-buflo") for cell in cells)
          and len({tuple(cell) for cell in cells}) == len(cells)
          and type(max_new_accepted) is int and 0 <= max_new_accepted <= 2615,
          "exact already-proved writer/cells/finite public budget required")
    _need(len(after["records"]) in (len(before["records"]), len(before["records"]) + 1)
          and _same(before["records"], after["records"][:len(before["records"])]), "Q/D/R public carry changed historical admission prefix")
    if len(after["records"]) == len(before["records"]):
        _need(_same(before["head"], after["head"]), "retained Q/D/R public stage changed admission head")
    def index(rows):
        _need(type(rows) is list and len(rows) <= 100000 and len({_key(row) for row in rows}) == len(rows),
              "bounded complete unique public accepted inventory required")
        return {_key(row): row for row in rows}
    previous = index(before["composition"]["accepted"])
    current = index(after["composition"]["accepted"])
    added = index(new_accepted)
    _need(previous.keys() <= current.keys() and all(_same(row, current[key]) for key, row in previous.items())
          and added.keys() == current.keys() - previous.keys() and len(added) <= max_new_accepted,
          "all and only whole-proved new active rows are required")
    scope = {tuple(cell) for cell in cells}
    for key, row in added.items():
        _need(_same(row, current[key]) and row["root"] == writer_root and (row["hostname"], row["mode"]) in scope,
              "whole-proved new active row escaped its original public scope")
    value = deepcopy(partition)
    value["qualified_accepted"] = _ordered([*partition["qualified_accepted"], *added.values()])
    active = _ordered(list(current.values()))
    historical = _ordered([*active, *partition["retired_accepted"]])
    for name, rows in (("qualified_accepted", value["qualified_accepted"]),
                       ("active_accepted", active), ("full_local_accepted", historical)):
        value[name + "_count"] = len(rows)
        value[name + "_inventory_sha256"] = e._sha(rows)
    _need(_same(value["deferred_accepted"], partition["deferred_accepted"])
          and _same(value["retired_accepted"], partition["retired_accepted"]),
          "public carry cannot promote pending rows or rewrite retired history")
    checked_active_partition(value, after)
    return value


