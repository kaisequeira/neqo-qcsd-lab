"""Exact dated readers through Source089 and explicit Source090 execution.

The separately qualified five-small-response BuFLO capability retains every
older immutable admission profile and the original physical packet guards.
No registry binding grants receipt, admission or scientific credit.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat

LEGACY_HEAD = "bd6f8afbc7c450b8e03d4b3814da75b68218c66e"
HELPER_NAME = "resource_study_reader_compatibility.py"
EXECUTION_KIND = '090'
BINDING_TYPE = 'qcsd-resource-domain-017-018-019-045-048-051-055-060-061-062-063-069-070-071-079-080-081-082-083-088-089-090-reader-execution-binding-v1'
PRIMARY_FILES = (
    "resource_study_verify.py", "resource_study_inputs.py", "fidelity.py",
    "resource_study_native.py", "resource_study_network.py",
    "resource_study_selection.py", "resource_study_lineage.py",
    "kernel_tx.py", "process_scheduler.py", "capture.py",
)
LEGACY_FILES = {'__init__.py': 'a768d2af1e7b99c92b4cdfb6e74530c26d922ff79669df367eabfac06df1433a',
 'acquisition_errors.py': 'a271797308e8fc55abcf861b79e6869564c84083b4b0f8b4faab8ee6bd8b8e02',
 'acquisition_selection.py': 'c649eed77cf853f288389f0f90c216c1c1046cf6d1ce5c12dd3e5939dfe75486',
 'acquisition_timing.py': '51203d06009b3b792f1a39e4e7cb06f95c92519ffb7f8408484043a33c5c91e0',
 'application_response_policy.py': '817e48d727bcb5b056f37582c8c469af7070deabbd367571c2ea05b9f36ac49a',
 'browser_egress.py': '8224c602320dab9d763e26a74e0da4dd57d2891c3eadfcea749b255801ec862b',
 'browser_egress_dns.py': '12fdcca81ab4fc7c96552fba1554e826a7455624ea722272a1eb4a3598460540',
 'browser_egress_dns_evidence.py': '57181f9a651ae0203010087362f706eb6f381716a16dc4d033acf26f7e111ff8',
 'browser_egress_dns_packets.py': '8a8e465786fc335aef3a220b18846a34b35401fbca98a0c7fc95ae26f48c19c2',
 'browser_egress_fixture.py': '643e814d22711ff8b7144e316826f9d1c96beccb2d292e0de97ee59f89aab777',
 'browser_egress_observer.py': '2da6c7b7d5ff093434f7fe0446fcbc87c9fe432faa61df573fd2f3f5d05cca06',
 'browser_egress_qualification.py': '662d2720f04ea4413a28b7cae3e4fbc102ea9ab93cc35acc667c86fab2efcd1c',
 'buflo_duration_budget.py': 'eba7deab77a6d63c784c8b2adc5731ab0cc3e5106823f7f4a8dca7be8b893864',
 'buflo_evaluation.py': '5e19f7d613177fee434ee6ab13fcbebe7bb2ea5d622667610ef6369b78c33e17',
 'buflo_handoff.py': '5f5a1ab88639f4f92dbbb860fc195fa64823a806ada44a0f79e6bbc8be0802f2',
 'buflo_reference.py': '9d3903361085591e3c165847addba4c2b23f2fbe4aeade640dedd3f1c64349c1',
 'buflo_study.py': '34c223198ef3fe125124bcedb3c38cb43672e54668536586a8dd28d99cc93aec',
 'build_storage.py': '1045990eaaca578b946b75b762aada3021e049f42913ee6d2fc105ebeee22d22',
 'capture.py': 'c37a0444c62e77068891281fa72200bdc2c07192ee8e4e05a9832bfe1a681c99',
 'capture_acceptance_policy.py': 'c0b97f2b84e72e74360a3f57de857cd8fc04c73b0ac7bb22db48610d8a37951e',
 'capture_session.py': '9aac829db53d8bded43b935c7d1d5e751cc70207977cecb9291daa5c605d9e3f',
 'cdp_targets.py': '78a552a29d8da28e7ed44c3de0472e241417349de318569e6d304f564d8af812',
 'chaff_qualification.py': '9e62f38e1e9923821194a46f673a6770ce5032b60bf39c60d7cb6896f15c0a22',
 'class_acquisition.py': '062e0f4b1829f141a010027a1c2bd3f960a06bca305e91e49f20d52b971288de',
 'class_attestation.py': '78bcbb8ef7ff429ef5306545b37390926aae6d476947dc55e20692f4411ff28b',
 'class_campaigns.py': '9171fceb732ea25d82f257114805473adf057fad1511b5f1e5e5a6b3cebc7e2c',
 'class_capture20.py': '810f1fce039288c5dca9885466017239e6fa71bb74932da5628c2c79753183cf',
 'class_catalogue.py': '2729f1a5b8f6747ac884fa4a3141b4a9d7cfbf31312d013356b0d3df137d98c9',
 'class_cohort.py': '00db10f6d52000a81f04c5b12fe87e0b7c5d354dfb762a45160af1a1fe4a6851',
 'class_cohort20.py': '0b6a521329fd8640511357dd8271618edada4bf75568e5f87cdea32f4a534ecd',
 'class_curated_source.py': '037140efd73c1837155aa43598dfe9924e70df759a8d326b78974297b73f7c30',
 'class_evaluation.py': '53101abf719a337d5282cc646296cbe3241f9706bed770bf9f84b1a64c5b8d56',
 'class_final_selection20.py': 'b4e1b7c663058e5ef0d58f96a5c6461677d016b06d420d4136bc56de324c568d',
 'class_fitting.py': 'c2df49181e39805d0b10a46a62228bdfdb453a39219a92a9d002234c60b164ed',
 'class_handoff.py': 'd68ece9a934bdd8cb89b496ba738eebd1fb5be3c6407fc154c6941001bc5c3ba',
 'class_history20.py': '5ff1e43488754d19ad3e13639a2eb7679373d7b0f08e388ecb85ac4839039099',
 'class_layout.py': 'bfb42dca135bd8cc868f9993dd64497b29adb5e8c19a5f7988867cfef525fdf9',
 'class_pair_screening20.py': 'f4ec9ce713f0c9df34ea31777b31f3d4f54900cd658fb239ddfec3308f7f057f',
 'class_pipeline.py': 'bb51dc7c6ab6c3b054edb093b39ff6b967bef0be2f9b9122136749e64e58a210',
 'class_profile_result.py': '751f3e538dfb8dfde58b90d52b82c6cd8a72f904a4868b68038be2d413abbbab',
 'class_public20.py': 'e395820fb95543ddce218abe30f74aceec23423940d57ee4099c905403d602fc',
 'class_readiness20.py': '4540743c6e37e9cefb2d5d7b6aec02e53be77b581171f45ef01e01acf8a9c6be',
 'class_run_binding.py': '96d396f8f44a992dfa68389c8ecf0fedbe221c751e6b6079291ca3dc5b0ddccf',
 'class_study.py': '8446d39ecd464224cd490f8907f16154087e100be0239f797ac69de1224c5985',
 'class_successor.py': '9bf2d695d202dc5c96b38c66714437281c1de25746705ba1fb7676a0df88492b',
 'class_validation20.py': '871697b428554b4ff1fa89d33e070c2e7ce3c672f0a7462e31fc92a9727c14c7',
 'cohort_allocation.py': 'bb01bc5ee8cbf24da2cc07d655388ffa5237ff0d5887c69ff572484f7413945e',
 'defenses.py': '4cb93c2f1e201d44576b0dbdf5b271912ec495fa5d931802b9dfd470d0a78428',
 'discover.py': '0da7cdc16b316e56a6fac4e76a4d2e9e6d9f57943ad031b36746e9e66fe9bf16',
 'discovery_evidence.py': 'cede18fe878b4e8fb94ed0d86ee7fbd3f59951259a19a8b3e798ee60fdee1551',
 'experiment.py': '8b0a594270c5c5652e073abdf7eac92de8d1170fdba4f8b73882e2f88f444251',
 'fidelity.py': '6158ab4bdb6ac5f72bca472db70946bbc05cf113e03100bd09bc3971a30fc285',
 'fitting.py': 'b3bc417b9ccc26f80d0a06e74bf0b72198aa58a2622c44acc8022a2ea4c176ee',
 'fitting_morphing.py': '1171e7040943d4ea678f72d5e8fe9a668f4267615d5be73a54d580166776dea7',
 'fitting_trace.py': 'a14781a05a4c1ac5c7a77b5267eee5a87a885e804c99418c0cc3a02ecbfe0567',
 'fitting_walkie_talkie.py': '6e259ddb10bc5c61090eaca358e3c44207a699e55099a2919ebdf3aff2d89931',
 'fitting_wtfpad.py': 'd322946b8e247a2b557881ee9b965008e6b0ed12b33bf97d2a3b749b20eb245e',
 'front_fixed_configuration.py': '512bdfeda75bdd305394e4e4580fe065744604f0d3a8e913c521dffef2448cca',
 'front_incoming_acceptance.py': 'f6d9d9afedbaad1e8f6fc6c650f3048293bdeff03c22895f0afdb3400c72cbf5',
 'front_preparation_evidence.py': 'ad755419af203f8bdc63c542c3171cffcee139ca74672ef09a71fe8e540a904d',
 'h3_prebaseline.py': '85e54ee90690950859ba05be5af6bd81a82a737d841f269b66534afb972e0961',
 'kernel_tx.py': '3f2ff2bbf9c0d967bcfa1aeff6e217e1bf34bd80ec148b4a49379e4f07d09ffd',
 'kernel_tx_runtime.py': 'df0e156811946f607eddec328eec9fca65fec29dc333fbcefdd685c8d90d4fa5',
 'manifest.py': 'c0c736fe5099627f3bd3b9e91c62528602948c57bb55598d063c0dba83dc0b16',
 'orchestrator.py': '1f7c976b6e2d5104fd83a202b344ebae732050152b2a959d61865546d0ba6c6c',
 'parameters.py': 'b052ce35399bb8f819c6852346f33a6ca88e2a7de1d50712279c32f849d258ba',
 'per_class_selected_capture_amendment.py': '903a214dbb8c91368f37e3c5b8b21514b205eba5f8ed19a1ae4898fb1f839193',
 'pinned_cdp.py': 'e776b4d00daa31d57ab7979fde32577038d4f35ef855c7ff2b8e6c00c158578e',
 'playwright_driver.py': '8bcf22f024d6c59dc2448a53c32c888d11837cba5870dd2b222f534b03293662',
 'prepare.py': 'b9ecb4ed9135f1613cfb356778a13e29fc7249cf273dd6bbce320d878822d12b',
 'process_scheduler.py': 'bee4213504292059121871b94599a10b286f8776517e65c8022404fabe1555d0',
 'profiles.py': 'a27a2e985937108910f16d5e80a144631c22e228dd626993c4f65b5c2d77dd93',
 'qualification_control_authority.py': '5b1fa08aaa1a7219a66a29f0f17721f24a435680ecd7834556ed53e5fbe3c833',
 'qualification_delivery_compatibility.py': 'f5cc390c721c0e713fccabb2478492d71161587c6e7597f33f59a0cf34485d32',
 'rapid_action_local_source_facts.py': '55460a08b99461c5d29d30579605f5f79ce187e69db6657fbdd87399794ed744',
 'rapid_additive_static_enrollment.py': '5404821bf1bf087493d60076d33c5769748052f6301c352dccc6dae61e630670',
 'rapid_ael_fifteen_qualification.py': '3c70f1a4c4701eb61f6127717f896c9097fad6c8fa7206fb3290a99454d3d667',
 'rapid_attempt_failure_evidence.py': '360cc124b91c34b1b63a53347421cc20e085d87549897f8ef06190fda2a9009c',
 'rapid_browser_policy_evidence.py': 'c5c9368f7677ced0e9e416538a70a4aa46165aceb3f80916bf67e5a66c8c7f3e',
 'rapid_canary_control_bridge.py': '1f79c9f8541205d32ead7f7a060baade81842a673f0f4108f0d48b81edbb8029',
 'rapid_capture_control_compatibility.py': '5514a03a6ea93cd25c4dddf496dbd6f89bfb3a260d28246075d11ec439453f60',
 'rapid_capture_control_installation.py': '42432f06660924061b3e1f271d81672b2bb9254b7fb72a3582db5a6616745db6',
 'rapid_capture_plan.py': '3026e0687072a406160e6de25897306702dc255dcba173641a5caf43d56c2cb7',
 'rapid_capture_traffic.py': 'b525c043eb465d51f7f75e35181e02010102b4da01a04801bb2b9f6221bcae4f',
 'rapid_chunk_partial_lane.py': '12ba6b327f278ddef1faaade56b22d5a5b80a388fbf636f9e3cb648607108225',
 'rapid_class_epochs.py': '2ce4c3e9e98cd20b1a74132b622ec0e8ac0af998155099c7615046da31245395',
 'rapid_collector_failure_evidence.py': '2fa4b8082ec9ec095e76804bf0234929eaa482025d7a8aadd6c4e857e258745b',
 'rapid_enrolled_subgroup.py': '4bc7a868db19d594181df37e0201444c90b4dca12c82035b2cf0f95c49411ac6',
 'rapid_epoch_corpus.py': '774e0ed1024c89d6a9689d60ddb523cd188b48e87892d67135b6e8c222f7d1f2',
 'rapid_epoch_target_chunks.py': '8094d9837b3149538e9a7425e6addd5a4982d9eac323a43e7f60789b8eca1c3d',
 'rapid_epoch_target_parallel_schedule.py': 'afafcd1a114d886225e69f06271998cefc69d409415ce7c6e8fdb151d34b7790',
 'rapid_fixed_condition_target.py': '09659c871371b93e9b2c964b6f87bae919b941ef9faa89c07b73e521e02bceb0',
 'rapid_formal_parallel.py': '7ef2b3dc014d1efc25041da893289b8aab2f7168c13db33424b536172142d51a',
 'rapid_front_capture_amendment.py': 'c7c606cbb78d7ca8f259e5b4f64374a66d2aaf0e506fe36e7f2bbde4b4ab18b8',
 'rapid_front_quick_compatibility.py': '12693bb5ccf8903c75fdb4d2ba318628d1da2e18ab743cad77012dde88fe6580',
 'rapid_front_quick_profile.py': '37863d343522b7a59ac314873ee685ddc8b936f6915a59d8540cd140bde46816',
 'rapid_lane_evidence.py': '3034f3a1cebb6b23b422fd3df921c1ed685b24ba59b3ffd4aed719b55f377977',
 'rapid_mixed_implementation_target.py': 'fcb97be28badbe1379c7a1ae30030fcefa57143b947765065fd64688084e3a7c',
 'rapid_operation_facts.py': '0e6889b169b647048718107230e7a2c1f6c3c2171c16dfb2f327895b964c3938',
 'rapid_ordinary_canary_carry.py': '2f714f6b683c666ee2905a5833813e76e61e08d2109f4881e128530ae169859f',
 'rapid_ordinary_canary_retry.py': 'b953d7bf8f2dff39208a82e4626cf453b7c9cbb9a6389bf0641dd49433d8aa87',
 'rapid_ordinary_group_canary.py': '80c5de31f5365ded3349cce8bba09f635523f694ba51766f3112e94c4095ef4c',
 'rapid_ordinary_parallel_schedule.py': 'c527c1d8a2563fa93952baa642b58fece08adbed31abcb93a9dc86e12879f58f',
 'rapid_ordinary_transport_control.py': 'dbe5e59dc9c35bdc0de19e78fc22526f5fb0269992c69a011584510a3646f4ca',
 'rapid_original_static_parallel_schedule.py': '1d56694bc5f9609f4c6fbfed0505b68eaeb5e1c04eed4d0acaaeb11b51ec5d87',
 'rapid_page_evidence.py': '2bd12ae74df7aef48c1071fcb71ccebc808d229adf688cf6a3c349a5264914de',
 'rapid_parallel_capture.py': '8d7003ac0b3ecb91aafdd48a0bb5d30deba2b64166f4433454d99c90d12a0ba1',
 'rapid_parallel_partial_lane.py': 'f29ca1f093c73639b4ccedd38627e3b9efb84bbf6e979f3ab5b68800262dd509',
 'rapid_partial_lane.py': '0c32fde26a13c4602a88b314ca4deb73d47c4f89b769ec6a5e527ebce7bcf4c4',
 'rapid_partial_progress.py': 'b4c7e618fc1bb8a666fef64814385299d5d5d07090109b05c31abfd063fd4bbc',
 'rapid_per_class_selected_enrollment.py': '4f7f3a6fd67f077165496b92d62e9b81f1e0168d01ad3f11607b144a6124bee0',
 'rapid_per_class_selected_input.py': '2a437fbcf3bfdadaca558b22d1174058f1b56f6244ecb2f1e2cd82c3e8e6719e',
 'rapid_per_mode_native_target.py': '0492267ebb39499500deebadedd96a124262e66a11018724d820b586f9470abc',
 'rapid_portable_runtime.py': '55a3836ef6010c19589945706ec5936d53b3c8c26953f96a8b9607de104c07df',
 'rapid_quick_profile.py': '70d0fbed289b3f7362f0334717ec5a9f61d7575d6dcf125b87782f9ee8315e05',
 'rapid_rolling_capture.py': 'd0c7b2132fc1a15809a10605567b2cc21c5d41522ddab1ae8f2c0a6b7bd1fc26',
 'rapid_rolling_readiness.py': '31c6d8e871eb969995e3ba7b8de56a5fd8e633bdb82346348878d93c5734b155',
 'rapid_rolling_schedule.py': '925cc2c7d76e4c76f63b0c298ae10126f79eee70a74a708e631af0932f0fe2c6',
 'rapid_runtime_compatibility.py': '9eb9723731acd636db05094ee9217a30563067c58edd76554cd444d54d3481b0',
 'rapid_runtime_epochs.py': 'ee5aa0fddd4a9ab0c351148be1eba826f014773a365378cdff37dce0fefaf733',
 'rapid_runtime_inspector.py': '125c408970650ecc964a40efbf289bcaa664567528c39d1d16cb070e0e15bbfa',
 'rapid_selected_budget_input.py': '3f03bae31b667535adab316fea98cc34f19bf9292bc1b041f428eb3a02dee3cb',
 'rapid_selected_capture_input.py': '72933db93fef22fd599dce35b2ae27dd2f525b112bc6140134540d1f1cad1fb1',
 'rapid_selected_input_renewal.py': '5210e945b44079ff4ba5ea20eafc0f194676a9f108a71dfc9ff50fde954deff6',
 'rapid_selected_parallel_schedule.py': 'c9a48725095fc097bb0facd3751765c105c0bf2fc6abc028b44623fd2d2dddef',
 'rapid_selection_amendment.py': 'f7c46bf31224f6ee5bce0c67c6cf5e6a10c77b611dc4231d183828c0cd2e750b',
 'rapid_site_admission.py': '8f6ba8905a8a396c80de58cfa7fdfe1b7dac60eb02a80bc0f093bb9790ad3e6d',
 'rapid_slot_chunks.py': 'f69f212f29f8507246f9aa1136e169723afcf541e51dafee55c19c919fe1c06c',
 'rapid_static_parallel_schedule.py': '49f4011e88cf64ddc9856ba95577f225a0c5326bf6f8f2ebcabd16876f2b9da0',
 'rapid_study_profile.py': '3de3b40e0b609db836c673b55b16fe368147e95561d6d240654ccaf1491d7bb5',
 'rapid_supplemental_cohort.py': '2391723d90e339680c9d6b7d0ce31ab84b437f1a963ed1b166eb1237a49ed091',
 'rapid_target_chunks.py': '0ae03e5a8082397171ea2947382570355ff3b6d4282331184f3f48112925611b',
 'rapid_target_overlay_source.py': '4fc6b87abacb0de8bb8959a70cae60d0b514b2fe5dbbaa23ccfe86c95ea55cc2',
 'rapid_target_parallel_schedule.py': 'a678b73b8ab3aa80dae9947701fea7315f894d9674a8e92ca76795ac8c45fd49',
 'rapid_undefended_capture.py': 'd94871f581fa953fbd6a9fae272f7700b593949ce8a22d6d6b7d9cbe86223c9b',
 'resource_study.py': '073b61a1abfbe5e86b9ed4a9ba51d42472515c0c67267c82cdc762232e73b697',
 'resource_study_audit.py': 'ee81e0506787a5414c6bcad438a02c7a468065890285542eba0b5e7f43b891c8',
 'resource_study_cohorts.py': '4fcd0fb3271697b6c8369a8d75090af23f2829215fdd4357de8a6b4b65c4b2e9',
 'resource_study_epochs.py': '8d10bd355563fa675d1245a86a91c33b9482859886476e0d3d09a289ac842c6c',
 'resource_study_inputs.py': '899b78d50063eea6c30140397b2342d900701d44aed8f1bfe9afb30abe9ffd2b',
 'resource_study_integrity.py': '7ce3265d78ca7d88714e8018fe36b88a04b52276dd6fd07108fe9ec128af7b12',
 'resource_study_lineage.py': '5f8633b96f5d6485cf785dd24d037c8933e074ceb03d268ff9ed04546ac444f4',
 'resource_study_native.py': '073c07672f652f0d4a9a1ba53b8010684ace6bc8fa1b3ed67ea4ef4b64d75976',
 'resource_study_network.py': '23a526aea2f1cfe2e36a0e1ae6f612d369d12af0c84efedbfe80270112d638a2',
 'resource_study_runtime.py': '291432420d40812fbaf4f8b2e23455c2076eb29a19d3d4e14b2860f9be344d0e',
 'resource_study_selection.py': '8c6b62481f90a2577b1b576c3de84a7c76b9703095376d200f48517b06e81927',
 'resource_study_storage.py': '20d4562f42461609c51c00f514eb22edebd8b123bb3824b3377a44b5f3a63db1',
 'resource_study_store.py': '22b55cc549c7c348d48dc9b24f9393ab88d09819424b97731a8f1cbc4b51c44a',
 'resource_study_supplements.py': '519b77d8f8305a8e77ad88f541f75a2e69845c8bdbb09a8192043f0a56042f2b',
 'resource_study_verify.py': '25e165e6f24f1ad5290d402b0924af9b14e97d37d879ad46e21cda320b584379',
 'response_budget_qualification.py': '09ceff4cdb80f25f2240e59560019a42cd6853d1eac61bac4aab424c59e0a3ec',
 'runtime_provenance.py': '7cf2811cc01a13f135abbc450b63be9e8b048b81ace7b78c1cc12e986f316370',
 'selected_capture_amendment.py': '99fb53c75a8f04772e2c431679900c3a5aeeeb8fd31b3176ee3a2923948b89dd',
 'static_budget_capture.py': 'a3749bad59ebf621cb570499437b5b44e603601c83b1fa3f506a439c22c8616a',
 'static_budget_capture_amendment.py': 'be14d1abdc4f363a69830ed0dbbc93f1fc1140b52a30d27df5ee54652abf78b1',
 'static_evidence_transport.py': '1be1c7055d52e18034f83be9b27cb3966df044d2f33e2c5e97b142de8d1e6892',
 'supplied_static_admission.py': 'f33350761098c2b39811b45dd12e9fa3608483cf0de8d5761f68ab0a3d4985fc',
 'supplied_static_bootstrap_get.py': '4a53baeb9f66220b6108ea304f54dd834fc447a4cc43f58a358de018b421f692',
 'supplied_static_budget_successor.py': 'a297fd337517ddffc30fc6e08b5961e2556f9311cbe5f7837baa0209bcf298d1',
 'supplied_static_capture_amendment.py': '8f3825139a109b1e25b9b74aaf5e59e14f1da7d4903e9998beae8497ad99a4e0',
 'supplied_static_get.py': 'ce20fe5b5d60f7b268b7eb659ab56e98048d5934bc9cb3b456e2ef99c330d322',
 'supplied_static_graph.py': '87370d25d526a22cac7519a721aed0db19b72fa5957a353301782779409d4efa',
 'supplied_static_preparation.py': '087ebcea7cf8c793a82cbf40bcb0e77fb1555ba50b648c02af85e52c76641f44',
 'tamaraw_fixed_configuration.py': '50ce06e201a6e93f1039be3352d2ef9743e75aa07536da54441ae7c1157a7117',
 'util.py': 'd4d3f35cf86360c3b40b0ae21f5845444439369b0b27c86be7d0e31d2216da76',
 'verification.py': 'eefa2db21755b28ba2c5ad34a570243a2770948115f08cb4a6f492e97488d497',
 'whole_graph_capture_amendment.py': '780a8eeafe671e7a8f66ec04484d3bb1e8317711806d219e8906fad860369e48',
 'whole_graph_input.py': '53a988148197bac97578cc89b5ca528f2cda6ea818b53a772f6f1302ae5c5ba8',
 'whole_graph_supplement.py': 'dd7c5973f6876acdadb079b5b33bd719918cffd0a5ad9847e7b54493d157af98'}

# The exact prior execution graph remains an immutable admission profile.
PRIOR_EXECUTION_FILES = {
    "resource_study_cohorts.py": "3b5d3d7bf3e33c73723f5c5c70da5fc006dfe0c007a98cdc68503710926d69d7",
    "resource_study_store.py": "76f49cb2f9e1a5788e4af073c7242125b3a689b414210e856fad0ed51a93ae53",
    "resource_study_reader_compatibility.py": "6922c4e3ca971459758f8b5e09f2c86d3c53999e7ff08a9411a411ca155ec87f",
}

# Exact frozen Source019 execution, reconstructed as a complete 170-file map.
# Its admission/receipt identity remains distinct from the executing reader.
PRIOR_CAPTURE_HEAD = "7c474b65caa44cb07c4a67f9b647a4fb8d44e355"
PRIOR_CAPTURE_EXECUTION_FILES = {
    "resource_study_cohorts.py": "3b5d3d7bf3e33c73723f5c5c70da5fc006dfe0c007a98cdc68503710926d69d7",
    "resource_study_store.py": "76f49cb2f9e1a5788e4af073c7242125b3a689b414210e856fad0ed51a93ae53",
    "resource_study.py": "dfba1a39876472c1e5e35e2cbabd0e4eb6f32fc33728d707eea3c96f1f3dd7f6",
    "resource_study_runtime.py": "03c2c7c2dc875d81610f53a8c0f28fccb3e69756b4c9a2af3cba9ef645c6ad4b",
    "resource_study_reader_compatibility.py": "e30d340542260c0f372582d95f063b61d984cd4f7bf55e1b68eb3f1e7499714c",
}

# Exact Source045 analysis execution, including its own frozen helper identity.
# This complete historical graph retains the original monitor bytes.
PRIOR_ANALYSIS_EXECUTION_FILES = {
    'resource_study_cohorts.py': '07256a1008c8b4a1f7685aeebafaeb8717aad771ce27d47cc088352956ebcea8',
    'resource_study_store.py': '76f49cb2f9e1a5788e4af073c7242125b3a689b414210e856fad0ed51a93ae53',
    'resource_study.py': '49058ed6a5ba1f7fc5fe73ece77ee8b2e2e99fdb2079de5fee9b06fa7d150d03',
    'resource_study_runtime.py': 'd5c299a273c264c0b8e4c65cc86e43e22707ce23a3399a1f2a26d19623d8c923',
    'resource_study_network.py': 'd1be85c769642739238ffc1823d41ed28353e3d9c38a1e84b54f8973bd614c20',
    'fidelity.py': 'cac68404e45cc57005add05ddf16b7a5c81819dc9a04c92dbe900d7960dc103f',
    'buflo_handoff.py': 'cc667caa2f987550b2affd2280d59054838d480108c2fac6d1f145e7e960f418',
    'buflo_evaluation.py': '59c7398c9b1a85e9ac1382bc9d0df7dbcd46bd9bc157860d45afc7cbe775a50d',
    'resource_study_verify.py': '82f4bfafe4987f118bda6c3ba4b9cebe2a3a78414effbf198457df56020ba235',
    'resource_study_native.py': 'fbd8e9424720632e37b3f8ae6c8e022d5f451542ea49cc381abd10e7ca42cd41',
    'resource_study_epochs.py': '2a1b64cd23e45912b577f6fbb00bdcdc5587e824992b20696614b38d92e1f9e7',
    'capture_acceptance_policy.py': 'b0a6a61cbf177e843567c50bf928d60b9e3ad9eca113a68831114dd2876817c9',
    'resource_study_reader_compatibility.py': '33fca2234bac94f484a0a917564f4e2ccbd83d0eb86bc74aa2fca9c941277d7a',
}

# Exact dated Source048 flight-authority and Source051 monitor profiles.
# Their original helper and monitor bytes remain distinct from current060.
PRIOR_FLIGHT_EXECUTION_FILES = {'buflo_evaluation.py': '59c7398c9b1a85e9ac1382bc9d0df7dbcd46bd9bc157860d45afc7cbe775a50d',
 'buflo_handoff.py': 'cc667caa2f987550b2affd2280d59054838d480108c2fac6d1f145e7e960f418',
 'capture_acceptance_policy.py': 'b0a6a61cbf177e843567c50bf928d60b9e3ad9eca113a68831114dd2876817c9',
 'fidelity.py': 'cac68404e45cc57005add05ddf16b7a5c81819dc9a04c92dbe900d7960dc103f',
 'resource_study.py': 'ab0826f8a1cf0b1b2dc87b627f0db04ae79922a63b49d4f88f38b151ce8f3117',
 'resource_study_cohorts.py': '1bbc93c44930c0498ec399d7136661009106fee8710fe229ef38f93fcbafa653',
 'resource_study_epochs.py': '31ca54fd09cfc05c6ac94c1e11855638acfba8dd7d165cea0c7347beddebaf8e',
 'resource_study_native.py': 'fbd8e9424720632e37b3f8ae6c8e022d5f451542ea49cc381abd10e7ca42cd41',
 'resource_study_network.py': 'd1be85c769642739238ffc1823d41ed28353e3d9c38a1e84b54f8973bd614c20',
 'resource_study_reader_compatibility.py': 'b311f12def021f4f7becaccaa62a9bf74994e8b07f10878176e64f11a2ba79da',
 'resource_study_runtime.py': '8b4628cb5f25e9db9181e32373f52364b21c22626a5baf0e7aa73a01b6b889c2',
 'resource_study_store.py': '9be2314336482cbceded42b61d70a161add53c1dd74f06d474ce711b0f9656fb',
 'resource_study_verify.py': '82f4bfafe4987f118bda6c3ba4b9cebe2a3a78414effbf198457df56020ba235'}

PRIOR_MONITOR_EXECUTION_FILES = {'buflo_evaluation.py': '59c7398c9b1a85e9ac1382bc9d0df7dbcd46bd9bc157860d45afc7cbe775a50d',
 'buflo_handoff.py': 'cc667caa2f987550b2affd2280d59054838d480108c2fac6d1f145e7e960f418',
 'capture_acceptance_policy.py': 'b0a6a61cbf177e843567c50bf928d60b9e3ad9eca113a68831114dd2876817c9',
 'fidelity.py': 'cac68404e45cc57005add05ddf16b7a5c81819dc9a04c92dbe900d7960dc103f',
 'process_scheduler.py': '8171b841d4aa26d63c9de740f79641bd4071ad1c9587dfc0d7068d5dac4328bf',
 'resource_study.py': '49058ed6a5ba1f7fc5fe73ece77ee8b2e2e99fdb2079de5fee9b06fa7d150d03',
 'resource_study_cohorts.py': '07256a1008c8b4a1f7685aeebafaeb8717aad771ce27d47cc088352956ebcea8',
 'resource_study_epochs.py': '2a1b64cd23e45912b577f6fbb00bdcdc5587e824992b20696614b38d92e1f9e7',
 'resource_study_native.py': 'fbd8e9424720632e37b3f8ae6c8e022d5f451542ea49cc381abd10e7ca42cd41',
 'resource_study_network.py': 'd1be85c769642739238ffc1823d41ed28353e3d9c38a1e84b54f8973bd614c20',
 'resource_study_reader_compatibility.py': 'c7d4f5a9983b7f09f82f0279188136b287662adbf41a303630e8cc01eb582e93',
 'resource_study_runtime.py': 'd5c299a273c264c0b8e4c65cc86e43e22707ce23a3399a1f2a26d19623d8c923',
 'resource_study_store.py': '76f49cb2f9e1a5788e4af073c7242125b3a689b414210e856fad0ed51a93ae53',
 'resource_study_verify.py': '82f4bfafe4987f118bda6c3ba4b9cebe2a3a78414effbf198457df56020ba235'}

# Source029 waits finitely for the exact joined pool's kernel-thread teardown.
# Source028 reuses successful pure network validation within one records call.
# Source027 checks the actual executor's owned threads after joining and keeps
# surviving foreign threads confined to the same residual auxiliary CPUs.
# Source024's worker partition and main-thread restoration are retained.
# Source023 immutable frozen manifests within one records() call are retained.
# Source022 startup eligibility and the immutable profile-byte cache remain.
# Actual helper bytes enter execution_files() below.
# An empty mapping refuses execution; no prospective hash is accepted.
# Source042 binds both outgoing clock frames to the exact modern kernel proof.
# Source045 analysis metrics retain the strictly validated retired primary cell.
# Source051's per-task ESRCH monitor correction remains byte whole.
# Source055 reuses the exact Source048 five-file flight-authority implementation.
# Exact dated Source055 projection, including its original helper bytes.
PRIOR_AUTHORITY_EXECUTION_FILES = {'buflo_evaluation.py': '59c7398c9b1a85e9ac1382bc9d0df7dbcd46bd9bc157860d45afc7cbe775a50d', 'buflo_handoff.py': 'cc667caa2f987550b2affd2280d59054838d480108c2fac6d1f145e7e960f418', 'capture_acceptance_policy.py': 'b0a6a61cbf177e843567c50bf928d60b9e3ad9eca113a68831114dd2876817c9', 'fidelity.py': 'cac68404e45cc57005add05ddf16b7a5c81819dc9a04c92dbe900d7960dc103f', 'process_scheduler.py': '8171b841d4aa26d63c9de740f79641bd4071ad1c9587dfc0d7068d5dac4328bf', 'resource_study.py': 'ab0826f8a1cf0b1b2dc87b627f0db04ae79922a63b49d4f88f38b151ce8f3117', 'resource_study_cohorts.py': '1bbc93c44930c0498ec399d7136661009106fee8710fe229ef38f93fcbafa653', 'resource_study_epochs.py': '31ca54fd09cfc05c6ac94c1e11855638acfba8dd7d165cea0c7347beddebaf8e', 'resource_study_native.py': 'fbd8e9424720632e37b3f8ae6c8e022d5f451542ea49cc381abd10e7ca42cd41', 'resource_study_network.py': 'd1be85c769642739238ffc1823d41ed28353e3d9c38a1e84b54f8973bd614c20', 'resource_study_runtime.py': '8b4628cb5f25e9db9181e32373f52364b21c22626a5baf0e7aa73a01b6b889c2', 'resource_study_store.py': '9be2314336482cbceded42b61d70a161add53c1dd74f06d474ce711b0f9656fb', 'resource_study_verify.py': '82f4bfafe4987f118bda6c3ba4b9cebe2a3a78414effbf198457df56020ba235', 'resource_study_reader_compatibility.py': 'd96cc949f72ee1f598127120ece848c4c6010bf44b9c9697b3711258087785f5'}

PRIOR_FROZEN_MANIFEST_EXECUTION_FILES = {'buflo_evaluation.py': '59c7398c9b1a85e9ac1382bc9d0df7dbcd46bd9bc157860d45afc7cbe775a50d', 'buflo_handoff.py': 'cc667caa2f987550b2affd2280d59054838d480108c2fac6d1f145e7e960f418', 'capture_acceptance_policy.py': 'b0a6a61cbf177e843567c50bf928d60b9e3ad9eca113a68831114dd2876817c9', 'fidelity.py': 'cac68404e45cc57005add05ddf16b7a5c81819dc9a04c92dbe900d7960dc103f', 'process_scheduler.py': '8171b841d4aa26d63c9de740f79641bd4071ad1c9587dfc0d7068d5dac4328bf', 'resource_study.py': '3e86436b99eea35f2266e74b86a778abc83b3a84161ee20bb76eadbb9c2a3510', 'resource_study_cohorts.py': '1bbc93c44930c0498ec399d7136661009106fee8710fe229ef38f93fcbafa653', 'resource_study_epochs.py': '31ca54fd09cfc05c6ac94c1e11855638acfba8dd7d165cea0c7347beddebaf8e', 'resource_study_native.py': '5a18d9b703d6401f078ddde14b2e3b92dde2db2286d3f2cc6130c1b7fcaa17e1', 'resource_study_network.py': 'd1be85c769642739238ffc1823d41ed28353e3d9c38a1e84b54f8973bd614c20', 'resource_study_runtime.py': '1d9cc9349d03de64c58c1d88d82c66eac787a4fa6f69c35bdf6c7b465e046ed4', 'resource_study_store.py': '9be2314336482cbceded42b61d70a161add53c1dd74f06d474ce711b0f9656fb', 'resource_study_verify.py': '82f4bfafe4987f118bda6c3ba4b9cebe2a3a78414effbf198457df56020ba235', 'resource_study_selection.py': '6f06c6bef2953d6b480949281b4e889ad7412aca7f2e6bc3c500130234b0e99e', 'resource_study_reader_compatibility.py': 'fce7445b2c590b0ad5c3a194d444e35776fddbe9de3cd6c65552f454cbd59097'}

PRIOR_PRIMARY_PARTIAL_EXECUTION_FILES = {'buflo_evaluation.py': '59c7398c9b1a85e9ac1382bc9d0df7dbcd46bd9bc157860d45afc7cbe775a50d', 'buflo_handoff.py': 'b7063e52658d4df3660a7a8af080085ea8eb718605346acbcc6b6e6c126f5338', 'capture_acceptance_policy.py': 'b0a6a61cbf177e843567c50bf928d60b9e3ad9eca113a68831114dd2876817c9', 'fidelity.py': 'cac68404e45cc57005add05ddf16b7a5c81819dc9a04c92dbe900d7960dc103f', 'process_scheduler.py': '8171b841d4aa26d63c9de740f79641bd4071ad1c9587dfc0d7068d5dac4328bf', 'resource_study.py': '1bfffcd9541a2d517c38058a26af07d90dc63c97bb6d5241a022ffa8dc100c98', 'resource_study_cohorts.py': '1bbc93c44930c0498ec399d7136661009106fee8710fe229ef38f93fcbafa653', 'resource_study_epochs.py': '31ca54fd09cfc05c6ac94c1e11855638acfba8dd7d165cea0c7347beddebaf8e', 'resource_study_native.py': '5a18d9b703d6401f078ddde14b2e3b92dde2db2286d3f2cc6130c1b7fcaa17e1', 'resource_study_network.py': 'd1be85c769642739238ffc1823d41ed28353e3d9c38a1e84b54f8973bd614c20', 'resource_study_runtime.py': '1d9cc9349d03de64c58c1d88d82c66eac787a4fa6f69c35bdf6c7b465e046ed4', 'resource_study_store.py': '9be2314336482cbceded42b61d70a161add53c1dd74f06d474ce711b0f9656fb', 'resource_study_verify.py': '82f4bfafe4987f118bda6c3ba4b9cebe2a3a78414effbf198457df56020ba235', 'resource_study_selection.py': '6f06c6bef2953d6b480949281b4e889ad7412aca7f2e6bc3c500130234b0e99e', 'resource_study_reader_compatibility.py': '128c45fed0f6e11f056d0894f6af9bd63b1655244c822d20ed02acc50d278505'}

PRIOR_FIN_PERMISSION_EXECUTION_FILES = {'buflo_evaluation.py': '834ee1c17a6b43852069e8fe9802e097f004fd1affb784f76021fcd72fd4a33e', 'buflo_handoff.py': 'b80903bee2a0711caad475b817b31b7a143c8fed602fb0f2effb717ef48c2d85', 'capture_acceptance_policy.py': 'b0a6a61cbf177e843567c50bf928d60b9e3ad9eca113a68831114dd2876817c9', 'fidelity.py': 'cac68404e45cc57005add05ddf16b7a5c81819dc9a04c92dbe900d7960dc103f', 'process_scheduler.py': '8171b841d4aa26d63c9de740f79641bd4071ad1c9587dfc0d7068d5dac4328bf', 'resource_study.py': 'ccfe08152b70113b5955f9fc63e6f1dee6e9621bf2f9c569dec0dc46fdd79a26', 'resource_study_cohorts.py': '1bbc93c44930c0498ec399d7136661009106fee8710fe229ef38f93fcbafa653', 'resource_study_epochs.py': '31ca54fd09cfc05c6ac94c1e11855638acfba8dd7d165cea0c7347beddebaf8e', 'resource_study_native.py': '403a73779e8d16b0d927d711afe4846f7f243b7d8ab02b82aee95a8ca96d524f', 'resource_study_network.py': 'd1be85c769642739238ffc1823d41ed28353e3d9c38a1e84b54f8973bd614c20', 'resource_study_runtime.py': '1d9cc9349d03de64c58c1d88d82c66eac787a4fa6f69c35bdf6c7b465e046ed4', 'resource_study_store.py': '9be2314336482cbceded42b61d70a161add53c1dd74f06d474ce711b0f9656fb', 'resource_study_verify.py': '82f4bfafe4987f118bda6c3ba4b9cebe2a3a78414effbf198457df56020ba235', 'resource_study_selection.py': '6f06c6bef2953d6b480949281b4e889ad7412aca7f2e6bc3c500130234b0e99e', 'buflo_fin_permission.py': '08742d2ee4652ecbb43ef11fc98aa17299f02c94fc656867403989cda9917916', 'capture_session.py': 'b7207fbaf41fc5ed6171ac01368a6fdf89cbd02d26b924f3148240bd929bc949', 'resource_study_reader_compatibility.py': '3982fdc5b20de5dc9ee1e10d8582ab0a870029033e8075a0174349cabc13d273'}

PRIOR_CAPPED_COVER081_EXECUTION_FILES = {'buflo_duration_budget.py': 'c568b7d092ab76f4346b17d187a106e3a8cd2b8267ebcae387bd68437b643ec5', 'buflo_evaluation.py': '834ee1c17a6b43852069e8fe9802e097f004fd1affb784f76021fcd72fd4a33e', 'buflo_fin_permission.py': '08742d2ee4652ecbb43ef11fc98aa17299f02c94fc656867403989cda9917916', 'buflo_handoff.py': 'c5b0a6fac096717dd3b710398a179089e13d43deffc882b3da4d1444d0bc2c74', 'capture_acceptance_policy.py': '16761a8eae4c95fe2bbdc92087d9de23fa071e87fde3f5d0dcc0d556af77ee0b', 'capture_session.py': 'b7207fbaf41fc5ed6171ac01368a6fdf89cbd02d26b924f3148240bd929bc949', 'fidelity.py': '149fbf8049c359478f47427b2f5ae26252869454a24d00b0c6d8459abf533dd8', 'kernel_tx.py': '5f05c57af4dbf3ec37ef6fd9dcf43984b2d48e477a4e8ca435556ce4e2612125', 'parameters.py': '179d7f9d43be5adae9470727cc193524d2756dc54645830e6dce61ea4d903b82', 'process_scheduler.py': '8171b841d4aa26d63c9de740f79641bd4071ad1c9587dfc0d7068d5dac4328bf', 'resource_study.py': '8b1bc5887aaa00db637d4a75aaa22073f1f3dc0b3723e1fc7f817a906a58331d', 'resource_study_cohorts.py': '0b6e10ff93e72e633973b310fd123ecbe9c7160671f393ab6e087b494a105a68', 'resource_study_epochs.py': '48dbc2afa5e3c8fea2debd8e36a70aaf9ed5034a0a423b9f6b80116d0efab3b6', 'resource_study_native.py': '6565608516fad575b6f7065cf19aeb4959b2aff03b5233ebb1552102c9e363c0', 'resource_study_network.py': 'd1be85c769642739238ffc1823d41ed28353e3d9c38a1e84b54f8973bd614c20', 'resource_study_reader_compatibility.py': 'e290dfb4532456a07bd19152860fce84e066008e0497ec3a4ea8e01afec6d6cf', 'resource_study_runtime.py': 'db63162ef14f0c2c26e814411fac78505a6dc1352adb382c0564d402825458f2', 'resource_study_selection.py': '6f06c6bef2953d6b480949281b4e889ad7412aca7f2e6bc3c500130234b0e99e', 'resource_study_store.py': '9be2314336482cbceded42b61d70a161add53c1dd74f06d474ce711b0f9656fb', 'resource_study_verify.py': '82f4bfafe4987f118bda6c3ba4b9cebe2a3a78414effbf198457df56020ba235'}

PRIOR_BOUNDED_RETRY082_EXECUTION_FILES = {'buflo_duration_budget.py': 'c568b7d092ab76f4346b17d187a106e3a8cd2b8267ebcae387bd68437b643ec5', 'buflo_evaluation.py': '834ee1c17a6b43852069e8fe9802e097f004fd1affb784f76021fcd72fd4a33e', 'buflo_fin_permission.py': '08742d2ee4652ecbb43ef11fc98aa17299f02c94fc656867403989cda9917916', 'buflo_handoff.py': 'c5b0a6fac096717dd3b710398a179089e13d43deffc882b3da4d1444d0bc2c74', 'capture_acceptance_policy.py': '16761a8eae4c95fe2bbdc92087d9de23fa071e87fde3f5d0dcc0d556af77ee0b', 'capture_session.py': 'b7207fbaf41fc5ed6171ac01368a6fdf89cbd02d26b924f3148240bd929bc949', 'fidelity.py': '149fbf8049c359478f47427b2f5ae26252869454a24d00b0c6d8459abf533dd8', 'kernel_tx.py': '5f05c57af4dbf3ec37ef6fd9dcf43984b2d48e477a4e8ca435556ce4e2612125', 'parameters.py': '179d7f9d43be5adae9470727cc193524d2756dc54645830e6dce61ea4d903b82', 'process_scheduler.py': '8171b841d4aa26d63c9de740f79641bd4071ad1c9587dfc0d7068d5dac4328bf', 'resource_study.py': 'e5169ee3ce7613bf44482549c9399d9dc74c952f3be57e65c88f30192b4bbe0e', 'resource_study_cohorts.py': '0b6e10ff93e72e633973b310fd123ecbe9c7160671f393ab6e087b494a105a68', 'resource_study_epochs.py': '48dbc2afa5e3c8fea2debd8e36a70aaf9ed5034a0a423b9f6b80116d0efab3b6', 'resource_study_native.py': '6565608516fad575b6f7065cf19aeb4959b2aff03b5233ebb1552102c9e363c0', 'resource_study_network.py': 'd1be85c769642739238ffc1823d41ed28353e3d9c38a1e84b54f8973bd614c20', 'resource_study_reader_compatibility.py': '4d29400859548d1d275622f649c1bb3b813bc1afbd542d0cbb28b267f6cf9f6e', 'resource_study_runtime.py': 'db63162ef14f0c2c26e814411fac78505a6dc1352adb382c0564d402825458f2', 'resource_study_selection.py': '6f06c6bef2953d6b480949281b4e889ad7412aca7f2e6bc3c500130234b0e99e', 'resource_study_store.py': '9be2314336482cbceded42b61d70a161add53c1dd74f06d474ce711b0f9656fb', 'resource_study_verify.py': '82f4bfafe4987f118bda6c3ba4b9cebe2a3a78414effbf198457df56020ba235'}

APPROVED_EXECUTION_FILES = {'buflo_duration_budget.py': 'c568b7d092ab76f4346b17d187a106e3a8cd2b8267ebcae387bd68437b643ec5',
 'buflo_evaluation.py': '834ee1c17a6b43852069e8fe9802e097f004fd1affb784f76021fcd72fd4a33e',
 'buflo_fin_permission.py': '08742d2ee4652ecbb43ef11fc98aa17299f02c94fc656867403989cda9917916',
 'buflo_handoff.py': '804597c52dc10a03f87197a60f1e19f6743f27588eb8f739c0760bbe217cdbad',
 'capture_acceptance_policy.py': '908e0e82e2c9b7812fe736511f3933b1def07b21315bdec847908753217a5953',
 'capture_session.py': 'b7207fbaf41fc5ed6171ac01368a6fdf89cbd02d26b924f3148240bd929bc949',
 'chaff_qualification.py': '7314f7c35f23e75fdb5f4805a0e28799f7fcbec590fec7219fb3a42913684591',
 'fidelity.py': 'ed8eead6a555ead1687e1df75df7bc523afdbf87eb96440b91b783e166210c0f',
 'kernel_tx.py': '5f05c57af4dbf3ec37ef6fd9dcf43984b2d48e477a4e8ca435556ce4e2612125',
 'parameters.py': '179d7f9d43be5adae9470727cc193524d2756dc54645830e6dce61ea4d903b82',
 'process_scheduler.py': '8171b841d4aa26d63c9de740f79641bd4071ad1c9587dfc0d7068d5dac4328bf',
 'resource_study.py': '5b2f26826966c98e9fb9d123451d8684068b0935fa2307d00faa60629c376002',
 'resource_study_cohorts.py': 'b53907f613d9af9393991814bd4359f7f5bbe29bb54001dc1ce599cda228256a',
 'resource_study_epochs.py': '693912bc1ad354001f73a87adb49e5bd1b3909db831384458dbd8e7c11fce76b',
 'resource_study_native.py': '831ff8042c5c6a488b820c2aadce9d9fdcd1f6a0344668ff1b299de4a1af375e',
 'resource_study_network.py': 'd1be85c769642739238ffc1823d41ed28353e3d9c38a1e84b54f8973bd614c20',
 'resource_study_runtime.py': '1730e61c569d402dc8f7cc6280e50166ff4eaeeb3470d39586199ab84a08b167',
 'resource_study_selection.py': '6f06c6bef2953d6b480949281b4e889ad7412aca7f2e6bc3c500130234b0e99e',
 'resource_study_store.py': '9be2314336482cbceded42b61d70a161add53c1dd74f06d474ce711b0f9656fb',
 'resource_study_verify.py': 'dbe72ecaafdeae98da59e50810f62109a446d91c75dba01fb5bc5cd024fe9eb9'}

_SHA = re.compile(r"[0-9a-f]{64}\Z")


def _encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")


def _copy(value):
    return json.loads(_encoded(value))


# Exact former current Source063 graph, including its original helper.
PRIOR_EXPLICIT_PREPARED_POLICY_EXECUTION_FILES = {'buflo_evaluation.py': '834ee1c17a6b43852069e8fe9802e097f004fd1affb784f76021fcd72fd4a33e', 'buflo_handoff.py': 'b80903bee2a0711caad475b817b31b7a143c8fed602fb0f2effb717ef48c2d85', 'capture_acceptance_policy.py': 'b0a6a61cbf177e843567c50bf928d60b9e3ad9eca113a68831114dd2876817c9', 'fidelity.py': 'cac68404e45cc57005add05ddf16b7a5c81819dc9a04c92dbe900d7960dc103f', 'process_scheduler.py': '8171b841d4aa26d63c9de740f79641bd4071ad1c9587dfc0d7068d5dac4328bf', 'resource_study.py': 'fb83b1b3354c3b046befd8d903ded5d216fd712164e96a8e3bc278630669822d', 'resource_study_cohorts.py': '1bbc93c44930c0498ec399d7136661009106fee8710fe229ef38f93fcbafa653', 'resource_study_epochs.py': '31ca54fd09cfc05c6ac94c1e11855638acfba8dd7d165cea0c7347beddebaf8e', 'resource_study_native.py': '0ec9465af89aa50d040c4ba3f2c87c6bced1786892c447a569fd3f5cbef89a4d', 'resource_study_network.py': 'd1be85c769642739238ffc1823d41ed28353e3d9c38a1e84b54f8973bd614c20', 'resource_study_runtime.py': '1d9cc9349d03de64c58c1d88d82c66eac787a4fa6f69c35bdf6c7b465e046ed4', 'resource_study_store.py': '9be2314336482cbceded42b61d70a161add53c1dd74f06d474ce711b0f9656fb', 'resource_study_verify.py': '82f4bfafe4987f118bda6c3ba4b9cebe2a3a78414effbf198457df56020ba235', 'resource_study_selection.py': '6f06c6bef2953d6b480949281b4e889ad7412aca7f2e6bc3c500130234b0e99e', 'buflo_fin_permission.py': '08742d2ee4652ecbb43ef11fc98aa17299f02c94fc656867403989cda9917916', 'capture_session.py': 'b7207fbaf41fc5ed6171ac01368a6fdf89cbd02d26b924f3148240bd929bc949', 'resource_study_reader_compatibility.py': '85affe2e936de8e78ee62eb7ca28c03bf907f2cc310f45f1a1e49a1953e16f56'}


# Exact former complete FIN Source069 profile, with its original helper.
PRIOR_COMPLETE_FIN069_EXECUTION_FILES = {'buflo_evaluation.py': '834ee1c17a6b43852069e8fe9802e097f004fd1affb784f76021fcd72fd4a33e', 'buflo_handoff.py': 'b80903bee2a0711caad475b817b31b7a143c8fed602fb0f2effb717ef48c2d85', 'capture_acceptance_policy.py': 'b0a6a61cbf177e843567c50bf928d60b9e3ad9eca113a68831114dd2876817c9', 'fidelity.py': 'cac68404e45cc57005add05ddf16b7a5c81819dc9a04c92dbe900d7960dc103f', 'process_scheduler.py': '8171b841d4aa26d63c9de740f79641bd4071ad1c9587dfc0d7068d5dac4328bf', 'resource_study.py': 'fb83b1b3354c3b046befd8d903ded5d216fd712164e96a8e3bc278630669822d', 'resource_study_cohorts.py': 'e7569bf189039339823ac5c81636e5a92a7429444a87427f0f6551ed6d8ae538', 'resource_study_epochs.py': '31ca54fd09cfc05c6ac94c1e11855638acfba8dd7d165cea0c7347beddebaf8e', 'resource_study_native.py': '0ec9465af89aa50d040c4ba3f2c87c6bced1786892c447a569fd3f5cbef89a4d', 'resource_study_network.py': 'd1be85c769642739238ffc1823d41ed28353e3d9c38a1e84b54f8973bd614c20', 'resource_study_runtime.py': '1d9cc9349d03de64c58c1d88d82c66eac787a4fa6f69c35bdf6c7b465e046ed4', 'resource_study_store.py': '9be2314336482cbceded42b61d70a161add53c1dd74f06d474ce711b0f9656fb', 'resource_study_verify.py': '82f4bfafe4987f118bda6c3ba4b9cebe2a3a78414effbf198457df56020ba235', 'resource_study_selection.py': '6f06c6bef2953d6b480949281b4e889ad7412aca7f2e6bc3c500130234b0e99e', 'buflo_fin_permission.py': '08742d2ee4652ecbb43ef11fc98aa17299f02c94fc656867403989cda9917916', 'capture_session.py': 'b7207fbaf41fc5ed6171ac01368a6fdf89cbd02d26b924f3148240bd929bc949', 'resource_study_reader_compatibility.py': 'b95b495d831c55144d6da7836218cf29e33f20f5162a3e24fa1a641b50679f7c'}


# Exact original070 explicit1280 reader; its science/admissions are not relabelled.
PRIOR_EXPLICIT_DURATION070_EXECUTION_FILES = {'buflo_evaluation.py': '834ee1c17a6b43852069e8fe9802e097f004fd1affb784f76021fcd72fd4a33e', 'buflo_handoff.py': 'c5b0a6fac096717dd3b710398a179089e13d43deffc882b3da4d1444d0bc2c74', 'capture_acceptance_policy.py': '16761a8eae4c95fe2bbdc92087d9de23fa071e87fde3f5d0dcc0d556af77ee0b', 'fidelity.py': '149fbf8049c359478f47427b2f5ae26252869454a24d00b0c6d8459abf533dd8', 'process_scheduler.py': '8171b841d4aa26d63c9de740f79641bd4071ad1c9587dfc0d7068d5dac4328bf', 'resource_study.py': '75fc033a2c4d80dafba0d1e1e9b86cc9128a4af4f7abc1a3b4472b3c32c29047', 'resource_study_cohorts.py': 'e7569bf189039339823ac5c81636e5a92a7429444a87427f0f6551ed6d8ae538', 'resource_study_epochs.py': '31ca54fd09cfc05c6ac94c1e11855638acfba8dd7d165cea0c7347beddebaf8e', 'resource_study_native.py': '6565608516fad575b6f7065cf19aeb4959b2aff03b5233ebb1552102c9e363c0', 'resource_study_network.py': 'd1be85c769642739238ffc1823d41ed28353e3d9c38a1e84b54f8973bd614c20', 'resource_study_runtime.py': '984afdef4cd3e35b9c644dab791c14cd0aa96e6d0e740b52f8a06ea8ca0b34ec', 'resource_study_store.py': '9be2314336482cbceded42b61d70a161add53c1dd74f06d474ce711b0f9656fb', 'resource_study_verify.py': '82f4bfafe4987f118bda6c3ba4b9cebe2a3a78414effbf198457df56020ba235', 'resource_study_selection.py': '6f06c6bef2953d6b480949281b4e889ad7412aca7f2e6bc3c500130234b0e99e', 'buflo_fin_permission.py': '08742d2ee4652ecbb43ef11fc98aa17299f02c94fc656867403989cda9917916', 'capture_session.py': 'b7207fbaf41fc5ed6171ac01368a6fdf89cbd02d26b924f3148240bd929bc949', 'buflo_duration_budget.py': 'c568b7d092ab76f4346b17d187a106e3a8cd2b8267ebcae387bd68437b643ec5', 'parameters.py': '179d7f9d43be5adae9470727cc193524d2756dc54645830e6dce61ea4d903b82', 'resource_study_reader_compatibility.py': 'e7ce904306ca8fc289b6997089c722ccd4b53afd58efa83e831b7377eec404b3'}


# Exact former current Source071 execution, including its original helper.
PRIOR_EXPLICIT_BUDGET071_EXECUTION_FILES = {'buflo_evaluation.py': '834ee1c17a6b43852069e8fe9802e097f004fd1affb784f76021fcd72fd4a33e', 'buflo_handoff.py': 'c5b0a6fac096717dd3b710398a179089e13d43deffc882b3da4d1444d0bc2c74', 'capture_acceptance_policy.py': '16761a8eae4c95fe2bbdc92087d9de23fa071e87fde3f5d0dcc0d556af77ee0b', 'fidelity.py': '149fbf8049c359478f47427b2f5ae26252869454a24d00b0c6d8459abf533dd8', 'process_scheduler.py': '8171b841d4aa26d63c9de740f79641bd4071ad1c9587dfc0d7068d5dac4328bf', 'resource_study.py': 'a0b0d55e5b0d47686af342d94b702544f26303841863bd7743df745938158dbe', 'resource_study_cohorts.py': '631d5c71869053a6c023e33b98665626720c6e8a8f5a1aba34cec3c7a7543e4e', 'resource_study_epochs.py': '31ca54fd09cfc05c6ac94c1e11855638acfba8dd7d165cea0c7347beddebaf8e', 'resource_study_native.py': '6565608516fad575b6f7065cf19aeb4959b2aff03b5233ebb1552102c9e363c0', 'resource_study_network.py': 'd1be85c769642739238ffc1823d41ed28353e3d9c38a1e84b54f8973bd614c20', 'resource_study_runtime.py': '868129929c305573017cbb7843bcb067222bab9a6b13e2ccb0e84258812913be', 'resource_study_store.py': '9be2314336482cbceded42b61d70a161add53c1dd74f06d474ce711b0f9656fb', 'resource_study_verify.py': '82f4bfafe4987f118bda6c3ba4b9cebe2a3a78414effbf198457df56020ba235', 'resource_study_selection.py': '6f06c6bef2953d6b480949281b4e889ad7412aca7f2e6bc3c500130234b0e99e', 'buflo_fin_permission.py': '08742d2ee4652ecbb43ef11fc98aa17299f02c94fc656867403989cda9917916', 'capture_session.py': 'b7207fbaf41fc5ed6171ac01368a6fdf89cbd02d26b924f3148240bd929bc949', 'buflo_duration_budget.py': 'c568b7d092ab76f4346b17d187a106e3a8cd2b8267ebcae387bd68437b643ec5', 'parameters.py': '179d7f9d43be5adae9470727cc193524d2756dc54645830e6dce61ea4d903b82', 'resource_study_reader_compatibility.py': 'f059289c6be4a446d493334b1140211993f0a40c3fa5304ccbf538d0586ee710'}


# Exact dated Source079 execution: original helper, kernel reader and images.
PRIOR_QUEUED_HTTP079_EXECUTION_FILES = {'buflo_evaluation.py': '834ee1c17a6b43852069e8fe9802e097f004fd1affb784f76021fcd72fd4a33e', 'buflo_handoff.py': 'c5b0a6fac096717dd3b710398a179089e13d43deffc882b3da4d1444d0bc2c74', 'capture_acceptance_policy.py': '16761a8eae4c95fe2bbdc92087d9de23fa071e87fde3f5d0dcc0d556af77ee0b', 'fidelity.py': '149fbf8049c359478f47427b2f5ae26252869454a24d00b0c6d8459abf533dd8', 'process_scheduler.py': '8171b841d4aa26d63c9de740f79641bd4071ad1c9587dfc0d7068d5dac4328bf', 'resource_study.py': 'a0b0d55e5b0d47686af342d94b702544f26303841863bd7743df745938158dbe', 'resource_study_cohorts.py': '631d5c71869053a6c023e33b98665626720c6e8a8f5a1aba34cec3c7a7543e4e', 'resource_study_epochs.py': '31ca54fd09cfc05c6ac94c1e11855638acfba8dd7d165cea0c7347beddebaf8e', 'resource_study_native.py': '6565608516fad575b6f7065cf19aeb4959b2aff03b5233ebb1552102c9e363c0', 'resource_study_network.py': 'd1be85c769642739238ffc1823d41ed28353e3d9c38a1e84b54f8973bd614c20', 'resource_study_runtime.py': '868129929c305573017cbb7843bcb067222bab9a6b13e2ccb0e84258812913be', 'resource_study_store.py': '9be2314336482cbceded42b61d70a161add53c1dd74f06d474ce711b0f9656fb', 'resource_study_verify.py': '82f4bfafe4987f118bda6c3ba4b9cebe2a3a78414effbf198457df56020ba235', 'resource_study_selection.py': '6f06c6bef2953d6b480949281b4e889ad7412aca7f2e6bc3c500130234b0e99e', 'buflo_fin_permission.py': '08742d2ee4652ecbb43ef11fc98aa17299f02c94fc656867403989cda9917916', 'capture_session.py': 'b7207fbaf41fc5ed6171ac01368a6fdf89cbd02d26b924f3148240bd929bc949', 'buflo_duration_budget.py': 'c568b7d092ab76f4346b17d187a106e3a8cd2b8267ebcae387bd68437b643ec5', 'parameters.py': '179d7f9d43be5adae9470727cc193524d2756dc54645830e6dce61ea4d903b82', 'kernel_tx.py': '5f05c57af4dbf3ec37ef6fd9dcf43984b2d48e477a4e8ca435556ce4e2612125', 'resource_study_reader_compatibility.py': 'cda1b3bf000c6fa3454636c7a7d60d145f4fca4e6ccd031f37511d13e84d03d0'}


# Exact dated Source080 external coordinator/current-head and finite BF pool.
PRIOR_BF_POOL080_EXECUTION_FILES = {'buflo_evaluation.py': '834ee1c17a6b43852069e8fe9802e097f004fd1affb784f76021fcd72fd4a33e', 'buflo_handoff.py': 'c5b0a6fac096717dd3b710398a179089e13d43deffc882b3da4d1444d0bc2c74', 'capture_acceptance_policy.py': '16761a8eae4c95fe2bbdc92087d9de23fa071e87fde3f5d0dcc0d556af77ee0b', 'fidelity.py': '149fbf8049c359478f47427b2f5ae26252869454a24d00b0c6d8459abf533dd8', 'process_scheduler.py': '8171b841d4aa26d63c9de740f79641bd4071ad1c9587dfc0d7068d5dac4328bf', 'resource_study.py': '2058cdc53cfba9c65b6554449f9caeae26459f3324ae8a8890e29b4d93d625d5', 'resource_study_cohorts.py': '84b59afc772db6794bd4319ec048f42fbb87924fa1bbec701bb8cf647212696c', 'resource_study_epochs.py': '48dbc2afa5e3c8fea2debd8e36a70aaf9ed5034a0a423b9f6b80116d0efab3b6', 'resource_study_native.py': '6565608516fad575b6f7065cf19aeb4959b2aff03b5233ebb1552102c9e363c0', 'resource_study_network.py': 'd1be85c769642739238ffc1823d41ed28353e3d9c38a1e84b54f8973bd614c20', 'resource_study_runtime.py': 'db63162ef14f0c2c26e814411fac78505a6dc1352adb382c0564d402825458f2', 'resource_study_store.py': '9be2314336482cbceded42b61d70a161add53c1dd74f06d474ce711b0f9656fb', 'resource_study_verify.py': '82f4bfafe4987f118bda6c3ba4b9cebe2a3a78414effbf198457df56020ba235', 'resource_study_selection.py': '6f06c6bef2953d6b480949281b4e889ad7412aca7f2e6bc3c500130234b0e99e', 'buflo_fin_permission.py': '08742d2ee4652ecbb43ef11fc98aa17299f02c94fc656867403989cda9917916', 'capture_session.py': 'b7207fbaf41fc5ed6171ac01368a6fdf89cbd02d26b924f3148240bd929bc949', 'buflo_duration_budget.py': 'c568b7d092ab76f4346b17d187a106e3a8cd2b8267ebcae387bd68437b643ec5', 'parameters.py': '179d7f9d43be5adae9470727cc193524d2756dc54645830e6dce61ea4d903b82', 'kernel_tx.py': '5f05c57af4dbf3ec37ef6fd9dcf43984b2d48e477a4e8ca435556ce4e2612125', 'resource_study_reader_compatibility.py': '8d325565cb44610a1473b8cc474ee3fbdf4684a6a79c9b01eac83f7bb3405648'}


def _profile(files):
    return {"record_type": "qcsd-resource-domain-runtime-cohort-verifier-contract-v1",
        "schema_version": 1, "implementation": "resource-study-raw-v1",
        "files": {name: files[name] for name in PRIMARY_FILES},
        "transitive_source_sha256": hashlib.sha256(_encoded(files)).hexdigest(),
        "transitive_source_files": len(files),
        "transitive_source_scope": "complete declared package-import closure; conservative dormant branches included"}


def legacy_contract():
    """Return a copy of the exact authenticated 169-file admission contract."""
    return _profile(LEGACY_FILES)


def prior_execution_contract():
    """Exact Source018 qualifier; its receipt/epoch identity is never retagged."""
    files = dict(LEGACY_FILES)
    files.update(PRIOR_EXECUTION_FILES)
    return _profile(files)


def prior_capture_execution_contract():
    """Exact Source019 170-file qualifier, never an alias for Source020."""
    files = dict(LEGACY_FILES)
    files.update(PRIOR_CAPTURE_EXECUTION_FILES)
    return _profile(files)


def prior_analysis_execution_contract():
    """Exact Source045 170-file profile, never the current execution identity."""
    files = dict(LEGACY_FILES)
    files.update(PRIOR_ANALYSIS_EXECUTION_FILES)
    return _profile(files)


def prior_flight_execution_contract():
    """Exact dated Source048 graph with its original monitor and helper."""
    files = dict(LEGACY_FILES)
    files.update(PRIOR_FLIGHT_EXECUTION_FILES)
    return _profile(files)


def prior_monitor_execution_contract():
    """Exact dated Source051 graph, never an alias for Source055 execution."""
    files = dict(LEGACY_FILES)
    files.update(PRIOR_MONITOR_EXECUTION_FILES)
    return _profile(files)


def prior_authority_execution_contract():
    """Exact dated Source055 graph; it cannot qualify current Source060 code."""
    files = dict(LEGACY_FILES)
    files.update(PRIOR_AUTHORITY_EXECUTION_FILES)
    return _profile(files)


def prior_frozen_manifest_execution_contract():
    """Exact dated Source060 fce graph, never the current Source061 identity."""
    files = dict(LEGACY_FILES)
    files.update(PRIOR_FROZEN_MANIFEST_EXECUTION_FILES)
    return _profile(files)


def prior_primary_partial_execution_contract():
    """Exact dated Source061 170-file graph and original fourteen-file approval."""
    files = dict(LEGACY_FILES)
    files.update(PRIOR_PRIMARY_PARTIAL_EXECUTION_FILES)
    return _profile(files)


def prior_fin_permission_execution_contract():
    """Exact dated Source062 171-file graph and sixteen approved modules."""
    files = dict(LEGACY_FILES)
    files.update(PRIOR_FIN_PERMISSION_EXECUTION_FILES)
    return _profile(files)



def prior_explicit_prepared_policy_execution_contract():
    """Exact dated Source063 171-file profile; never current Source069."""
    files = dict(LEGACY_FILES)
    files.update(PRIOR_EXPLICIT_PREPARED_POLICY_EXECUTION_FILES)
    return _profile(files)


def prior_complete_fin069_execution_contract():
    """Exact dated Source069171 profile, never the prospective Source070 identity."""
    files = dict(LEGACY_FILES)
    files.update(PRIOR_COMPLETE_FIN069_EXECUTION_FILES)
    return _profile(files)


def prior_explicit_duration070_execution_contract():
    """Exact dated Source070171 profile, separate from the new071 coordinator."""
    files = dict(LEGACY_FILES)
    files.update(PRIOR_EXPLICIT_DURATION070_EXECUTION_FILES)
    return _profile(files)


def prior_explicit_budget071_execution_contract():
    """Exact dated Source071 coordinator profile, never current Source079."""
    files = dict(LEGACY_FILES)
    files.update(PRIOR_EXPLICIT_BUDGET071_EXECUTION_FILES)
    return _profile(files)


def prior_queued_http079_execution_contract():
    """Exact dated Source079 producer profile, never current Source080."""
    files = dict(LEGACY_FILES)
    files.update(PRIOR_QUEUED_HTTP079_EXECUTION_FILES)
    return _profile(files)


def prior_bf_pool080_execution_contract():
    """Exact dated Source080 pool/coordinator profile, never current Source081."""
    files = dict(LEGACY_FILES)
    files.update(PRIOR_BF_POOL080_EXECUTION_FILES)
    return _profile(files)


def prior_capped_cover081_execution_contract():
    """Exact dated Source081 capped-cover profile, never current Source082."""
    files = dict(LEGACY_FILES)
    files.update(PRIOR_CAPPED_COVER081_EXECUTION_FILES)
    return _profile(files)


def prior_bounded_retry082_execution_contract():
    """Exact dated Source082 bounded-retry profile, never current Source083."""
    files = dict(LEGACY_FILES)
    files.update(PRIOR_BOUNDED_RETRY082_EXECUTION_FILES)
    return _profile(files)


# Exact former current SDK083 profile, also used unchanged by Lab084 through Lab087.
PRIOR_OWNED_IMMUTABLE083_EXECUTION_FILES = {'buflo_duration_budget.py': 'c568b7d092ab76f4346b17d187a106e3a8cd2b8267ebcae387bd68437b643ec5',
 'buflo_evaluation.py': '834ee1c17a6b43852069e8fe9802e097f004fd1affb784f76021fcd72fd4a33e',
 'buflo_fin_permission.py': '08742d2ee4652ecbb43ef11fc98aa17299f02c94fc656867403989cda9917916',
 'buflo_handoff.py': 'c5b0a6fac096717dd3b710398a179089e13d43deffc882b3da4d1444d0bc2c74',
 'capture_acceptance_policy.py': '16761a8eae4c95fe2bbdc92087d9de23fa071e87fde3f5d0dcc0d556af77ee0b',
 'capture_session.py': 'b7207fbaf41fc5ed6171ac01368a6fdf89cbd02d26b924f3148240bd929bc949',
 'fidelity.py': '149fbf8049c359478f47427b2f5ae26252869454a24d00b0c6d8459abf533dd8',
 'kernel_tx.py': '5f05c57af4dbf3ec37ef6fd9dcf43984b2d48e477a4e8ca435556ce4e2612125',
 'parameters.py': '179d7f9d43be5adae9470727cc193524d2756dc54645830e6dce61ea4d903b82',
 'process_scheduler.py': '8171b841d4aa26d63c9de740f79641bd4071ad1c9587dfc0d7068d5dac4328bf',
 'resource_study.py': 'e5169ee3ce7613bf44482549c9399d9dc74c952f3be57e65c88f30192b4bbe0e',
 'resource_study_cohorts.py': 'b53907f613d9af9393991814bd4359f7f5bbe29bb54001dc1ce599cda228256a',
 'resource_study_epochs.py': '48dbc2afa5e3c8fea2debd8e36a70aaf9ed5034a0a423b9f6b80116d0efab3b6',
 'resource_study_native.py': '6565608516fad575b6f7065cf19aeb4959b2aff03b5233ebb1552102c9e363c0',
 'resource_study_network.py': 'd1be85c769642739238ffc1823d41ed28353e3d9c38a1e84b54f8973bd614c20',
 'resource_study_reader_compatibility.py': '7814c297ddf4dfa68110689ddb781007637e678c4e0e5f8582097873b19a4155',
 'resource_study_runtime.py': 'db63162ef14f0c2c26e814411fac78505a6dc1352adb382c0564d402825458f2',
 'resource_study_selection.py': '6f06c6bef2953d6b480949281b4e889ad7412aca7f2e6bc3c500130234b0e99e',
 'resource_study_store.py': '9be2314336482cbceded42b61d70a161add53c1dd74f06d474ce711b0f9656fb',
 'resource_study_verify.py': '82f4bfafe4987f118bda6c3ba4b9cebe2a3a78414effbf198457df56020ba235'}


def prior_owned_immutable083_execution_contract():
    """Exact dated Source083 graph; never the corrected current Source088."""
    files = dict(LEGACY_FILES)
    files.update(PRIOR_OWNED_IMMUTABLE083_EXECUTION_FILES)
    return _profile(files)


# Exact previous coordinator088 graph, including its original helper bytes.
PRIOR_MISSED_REASON088_EXECUTION_FILES = {'buflo_duration_budget.py': 'c568b7d092ab76f4346b17d187a106e3a8cd2b8267ebcae387bd68437b643ec5',
 'buflo_evaluation.py': '834ee1c17a6b43852069e8fe9802e097f004fd1affb784f76021fcd72fd4a33e',
 'buflo_fin_permission.py': '08742d2ee4652ecbb43ef11fc98aa17299f02c94fc656867403989cda9917916',
 'buflo_handoff.py': 'c5b0a6fac096717dd3b710398a179089e13d43deffc882b3da4d1444d0bc2c74',
 'capture_acceptance_policy.py': '16761a8eae4c95fe2bbdc92087d9de23fa071e87fde3f5d0dcc0d556af77ee0b',
 'capture_session.py': 'b7207fbaf41fc5ed6171ac01368a6fdf89cbd02d26b924f3148240bd929bc949',
 'fidelity.py': '1ee90f83469b7af9b54223219f29b0459172f38a06230718ba2ef590a987af12',
 'kernel_tx.py': '5f05c57af4dbf3ec37ef6fd9dcf43984b2d48e477a4e8ca435556ce4e2612125',
 'parameters.py': '179d7f9d43be5adae9470727cc193524d2756dc54645830e6dce61ea4d903b82',
 'process_scheduler.py': '8171b841d4aa26d63c9de740f79641bd4071ad1c9587dfc0d7068d5dac4328bf',
 'resource_study.py': 'e5169ee3ce7613bf44482549c9399d9dc74c952f3be57e65c88f30192b4bbe0e',
 'resource_study_cohorts.py': 'b53907f613d9af9393991814bd4359f7f5bbe29bb54001dc1ce599cda228256a',
 'resource_study_epochs.py': '48dbc2afa5e3c8fea2debd8e36a70aaf9ed5034a0a423b9f6b80116d0efab3b6',
 'resource_study_native.py': '6565608516fad575b6f7065cf19aeb4959b2aff03b5233ebb1552102c9e363c0',
 'resource_study_network.py': 'd1be85c769642739238ffc1823d41ed28353e3d9c38a1e84b54f8973bd614c20',
 'resource_study_reader_compatibility.py': '0c4237834d9a9b7f71db5f26e57102ecdc9a3b3b23275bd4c6a7164db083b807',
 'resource_study_runtime.py': 'db63162ef14f0c2c26e814411fac78505a6dc1352adb382c0564d402825458f2',
 'resource_study_selection.py': '6f06c6bef2953d6b480949281b4e889ad7412aca7f2e6bc3c500130234b0e99e',
 'resource_study_store.py': '9be2314336482cbceded42b61d70a161add53c1dd74f06d474ce711b0f9656fb',
 'resource_study_verify.py': '82f4bfafe4987f118bda6c3ba4b9cebe2a3a78414effbf198457df56020ba235'}


def prior_missed_reason088_execution_contract():
    """Exact dated Source088 coordinator; never the new Source089 pool role."""
    files = dict(LEGACY_FILES)
    files.update(PRIOR_MISSED_REASON088_EXECUTION_FILES)
    return _profile(files)


# Exact prior coordinator089 graph, including its original immutable registry.
PRIOR_NATIVE126_POOL089_EXECUTION_FILES = {'buflo_duration_budget.py': 'c568b7d092ab76f4346b17d187a106e3a8cd2b8267ebcae387bd68437b643ec5',
 'buflo_evaluation.py': '834ee1c17a6b43852069e8fe9802e097f004fd1affb784f76021fcd72fd4a33e',
 'buflo_fin_permission.py': '08742d2ee4652ecbb43ef11fc98aa17299f02c94fc656867403989cda9917916',
 'buflo_handoff.py': 'c5b0a6fac096717dd3b710398a179089e13d43deffc882b3da4d1444d0bc2c74',
 'capture_acceptance_policy.py': '16761a8eae4c95fe2bbdc92087d9de23fa071e87fde3f5d0dcc0d556af77ee0b',
 'capture_session.py': 'b7207fbaf41fc5ed6171ac01368a6fdf89cbd02d26b924f3148240bd929bc949',
 'fidelity.py': '1ee90f83469b7af9b54223219f29b0459172f38a06230718ba2ef590a987af12',
 'kernel_tx.py': '5f05c57af4dbf3ec37ef6fd9dcf43984b2d48e477a4e8ca435556ce4e2612125',
 'parameters.py': '179d7f9d43be5adae9470727cc193524d2756dc54645830e6dce61ea4d903b82',
 'process_scheduler.py': '8171b841d4aa26d63c9de740f79641bd4071ad1c9587dfc0d7068d5dac4328bf',
 'resource_study.py': '30623dc958ed82d5e7294a9d0ba0a98bf201217d9ec681f384a4c019e42a1636',
 'resource_study_cohorts.py': 'b53907f613d9af9393991814bd4359f7f5bbe29bb54001dc1ce599cda228256a',
 'resource_study_epochs.py': '48dbc2afa5e3c8fea2debd8e36a70aaf9ed5034a0a423b9f6b80116d0efab3b6',
 'resource_study_native.py': '6565608516fad575b6f7065cf19aeb4959b2aff03b5233ebb1552102c9e363c0',
 'resource_study_network.py': 'd1be85c769642739238ffc1823d41ed28353e3d9c38a1e84b54f8973bd614c20',
 'resource_study_reader_compatibility.py': 'd5c1304ef4fdab199020c9f5cd27cfb5ab789f56b3cfbad8a3d0b67e98786113',
 'resource_study_runtime.py': 'd97522e485d156e501b967ebe3f3b9bd562c27e1f683b176a8e82fe717822298',
 'resource_study_selection.py': '6f06c6bef2953d6b480949281b4e889ad7412aca7f2e6bc3c500130234b0e99e',
 'resource_study_store.py': '9be2314336482cbceded42b61d70a161add53c1dd74f06d474ce711b0f9656fb',
 'resource_study_verify.py': '82f4bfafe4987f118bda6c3ba4b9cebe2a3a78414effbf198457df56020ba235'}


def prior_native126_pool089_execution_contract():
    """Exact dated Source089 pool coordinator; never the Source090 aggregate role."""
    files = dict(LEGACY_FILES)
    files.update(PRIOR_NATIVE126_POOL089_EXECUTION_FILES)
    return _profile(files)


def _self_sha256():
    path = Path(__file__)
    if (not path.is_absolute() or path.resolve(strict=True) != path
            or any(p.is_symlink() for p in (path, *path.parents))):
        raise ValueError("compatibility helper Source path differs")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as handle:
        before = os.fstat(handle.fileno()); raw = handle.read(4 * 1024**2 + 1)
        after = os.fstat(handle.fileno())
    fields = ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_nlink",
              "st_size", "st_mtime_ns", "st_ctime_ns")
    stamp = lambda info: tuple(getattr(info, field) for field in fields)
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or len(raw) != before.st_size or len(raw) > 4 * 1024**2
            or stamp(before) != stamp(after) or stamp(after) != stamp(path.lstat())):
        raise ValueError("compatibility helper Source FD/path changed")
    return hashlib.sha256(raw).hexdigest()


def execution_files():
    """Expected 171-file graph; the caller supplies a freshly observed profile.

    The helper itself is included in that actual execution graph. ROOT's fixed
    execution/consumer Source manifest binds its exact bytes before launch.
    """
    if (set(APPROVED_EXECUTION_FILES) != {"resource_study_cohorts.py", "resource_study_store.py",
                                         "resource_study.py", "resource_study_runtime.py", "resource_study_network.py",
                                         "fidelity.py", "buflo_handoff.py", "buflo_evaluation.py", "resource_study_verify.py",
                                         "capture_acceptance_policy.py", "resource_study_native.py",
                                         "resource_study_epochs.py", "process_scheduler.py", "resource_study_selection.py",
                                         "capture_session.py", "buflo_fin_permission.py", "parameters.py", "buflo_duration_budget.py", "kernel_tx.py",
                                         "chaff_qualification.py"}
            or any(type(v) is not str or _SHA.fullmatch(v) is None
                   for v in APPROVED_EXECUTION_FILES.values())):
        raise ValueError("Source090 reader compatibility registry is not sealed")
    result = dict(LEGACY_FILES)
    result.update(APPROVED_EXECUTION_FILES)
    result[HELPER_NAME] = _self_sha256()
    return result


class _QualifiedExecution:
    __slots__ = ("_profile", "_supported_profiles")

    def __init__(self, profile):
        self._profile = _encoded(profile)
        # Serialize each exact immutable profile once per qualified reader,
        # rather than rebuilding/hashing whole Source maps for every member.
        self._supported_profiles = (
            _encoded(legacy_contract()),
            _encoded(prior_execution_contract()),
            _encoded(prior_capture_execution_contract()),
            _encoded(prior_analysis_execution_contract()),
            _encoded(prior_flight_execution_contract()),
            _encoded(prior_monitor_execution_contract()),
            _encoded(prior_authority_execution_contract()),
            _encoded(prior_frozen_manifest_execution_contract()),
            _encoded(prior_primary_partial_execution_contract()),
            _encoded(prior_fin_permission_execution_contract()),
            _encoded(prior_explicit_prepared_policy_execution_contract()),
            _encoded(prior_complete_fin069_execution_contract()),
            _encoded(prior_explicit_duration070_execution_contract()),
            _encoded(prior_explicit_budget071_execution_contract()),
            _encoded(prior_queued_http079_execution_contract()),
            _encoded(prior_bf_pool080_execution_contract()),
            _encoded(prior_capped_cover081_execution_contract()),
            _encoded(prior_bounded_retry082_execution_contract()),
            _encoded(prior_owned_immutable083_execution_contract()),
            _encoded(prior_missed_reason088_execution_contract()),
            _encoded(prior_native126_pool089_execution_contract()),
            self._profile,
        )

    def contract(self):
        return json.loads(self._profile)


def qualify_execution(actual):
    """Authenticate the exact approved Source090 profile, never a dated alias.

    This value is call-local Source metadata. It contains no head, SQL rows,
    reservations, accepted count, receipt, raw result or scientific proof.
    """
    expected = _profile(execution_files())
    if _encoded(actual) != _encoded(expected):
        raise ValueError("unsupported or changed Source090 execution reader")
    return _QualifiedExecution(expected)


def require_supported(admission, qualified):
    """Keep an exact original admission profile or the exact execution profile."""
    if type(qualified) is not _QualifiedExecution:
        raise ValueError("qualified Source090 execution reader required")
    if _encoded(admission) not in qualified._supported_profiles:
        raise ValueError("unsupported or changed admission reader / verifier contract")
    return True


def admission_contract(admission, qualified):
    require_supported(admission, qualified)
    return _copy(admission)


def execution_binding(admission, qualified):
    """Describe the source substitution without relabelling an old qualifier."""
    require_supported(admission, qualified)
    execution = qualified.contract()
    return {"record_type": BINDING_TYPE, "schema_version": 1,
        "admission_reader": _copy(admission), "execution_reader": execution,
        "admission_reader_preserved": True,
        "execution_reader_is_admission_reader": _encoded(admission) == qualified._profile,
        "compatibility_rule": "exact authenticated Source017/018/019 admission profiles, dated Source045/048/051/055/060/061/062/063/069/070/071/079/080/081/082/083/088/089 execution or reviewed Source090 execution profile",
        "changed_source_files": sorted(APPROVED_EXECUTION_FILES),
        "source090_qualified_five_small_response_aggregate_role_added": True,
        "source090_original_ordinary_qualification_and_startup_preserved": True,
        "source090_manifest_schema": 5,
        "source090_response_qualification_schema": 6,
        "source090_aggregate_startup_schema": 2,
        "source090_ordinary_allocator_kernel_and_packet_guards_preserved": True,
        "source089_exact_native126_multiroot_coordinator_role_added": True,
        "source089_native126_images_preparation_and_ownpilots_unchanged": True,
        "source089_original_scheduler_custody_quota_and_packet_gates_preserved": True,
        "source088_actual_missed_only_reason_aggregation_changed": True,
        "source088_raw_rows_congestion_and_primary_partial_gates_preserved": True,
        "source088_native_runtime_preparation_or_ownpilot_requirements_changed": False,
        "source083_owned_immutable_authority_observation_cache_changed": True,
        "source083_entry_and_exit_full_byte_validation_preserved": True,
        "source083_fresh_FD_SQL_source_and_ownership_fences_preserved": True,
        "source083_native_runtime_or_scientific_truth_conditions_changed": False,
        "source082_bounded_fresh_buflo_collector_retries_changed": True,
        "source082_buflo_max_consecutive_collector_failures": 3,
        "source082_native_runtime_or_scientific_truth_conditions_changed": False,
        "source081_same_runtime_capped_cover_admission_changed": True,
        "source081_native_runtime_or_scientific_truth_conditions_changed": False,
        "source080_current_head_metadata_view_changed": True,
        "source080_finite_native122_buflo_root_pool_changed": True,
        "source080_native_runtime_or_scientific_truth_conditions_changed": False,
        "allocator_control_implementation_changed": True,
        "shared_two_root_capture_launcher_changed": True,
        "outer_coordinator_auxiliary_affinity_scope_changed": True,
        "coordinator_pool_thread_closure_changed": True,
        "records_network_validation_cache_changed": True,
        "coordinator_kernel_thread_teardown_changed": True,
        "buflo_local_abandonment_reader_changed": True,
        "buflo_typed_partial_advertisement_observations_changed": True,
        "buflo_ack_start_retained_directory_binding_changed": True,
        "buflo_ack_start_retained_stop_schedule_changed": True,
        "buflo_ack_start_retained_evaluation_join_changed": True,
        "buflo_startup_ack_sparse_false_fin_changed": True,
        "buflo_capped_chaff_selection_changed": True,
        "buflo_outgoing_physical_clock_binding_changed": True,
        "buflo_terminal_primary_partial_metrics_reader_changed": True,
        "capture_scheduler_task_exit_race_monitor_changed": True,
        "capture_flight_authority_projection_changed": True,
        "frozen_application_manifest_preparation_changed": True,
        "cs_buflo_terminal_primary_partial_handoff_accounting_changed": True,
        "buflo_genuine_FIN_permission_release_independent_reader_changed": True,
        "buflo_explicit_native_permission_policy_launch_changed": True,
        "prospective_buflo_terminal_protocol_changed": True,
        "scientific_truth_conditions_changed": True,
        "historical_receipts_requalified_by_compatibility": False,
        "authority_issued": False, "scientific_credit_added": 0}
