"""HOST integration; original raw/progress real, new proof/runtime roles synthetic.

No original public physical validator, Docker, Native or network runs. The
controlled corpus reports exercise mapping only and cannot publish credit.
"""
import copy
import hashlib
import json
import os
from pathlib import Path

import pytest

from qcsd_lab import rapid_capture_plan as campaigns
from qcsd_lab import rapid_epoch_corpus as corpus
from qcsd_lab import rapid_operation_facts as facts
from qcsd_lab import rapid_per_class_selected_enrollment as ledger
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_slot_chunks as chunks
from tests.test_per_class_selected_budget import actual_q53_input, genuine_seed, fixture_enrollment
from tests.test_rapid_epoch_corpus import lane


def test_actual_sci9_gaps_are_not_inferred_from_accepted_count():
    path=Path(os.environ['QCSD_TEST_PRIOR_PROGRESS'])
    assert hashlib.sha256(path.read_bytes()).hexdigest()==os.environ['QCSD_TEST_PRIOR_PROGRESS_SHA256']
    value=json.loads(path.read_bytes())
    identities={row['candidate_id']:row['class_index'] for row in value['accepted_formal_slots']}
    _,slots,_=chunks.prior_progress(rolling._ref(path),[
        {'candidate_id':candidate,'class_index':index} for candidate,index in identities.items()])
    accepted={visit for index,mode,visit in slots if index==1 and mode=='tamaraw'}
    assert accepted==set(range(4))|set(range(12,32))
    assert chunks.ranges(accepted)==((4,8),(32,16),(48,16))
    assert len(slots)==36


def test_real_q53_budget_chunk_offsets_agree_with_cross_epoch_reader(
        actual_q53_input,genuine_seed,monkeypatch):
    enrollment,_,_,manifest=fixture_enrollment(actual_q53_input,genuine_seed,monkeypatch)
    owner=facts.OperationFacts()
    with owner.scope():
        batch,classes,policy=rolling._verify_enrollment(enrollment)
        selected=classes[-1]
        limits=rolling._effective_capture_limits(batch,classes,policy)
        assert limits['max_response_bytes']==64*1024*1024 and limits['capture_megabytes']==256
        value=json.loads(manifest.read_bytes())
        original_graph=hashlib.sha256(json.dumps(value['resources'],sort_keys=True,separators=(',',':')).encode()).hexdigest()
        site=campaigns.Site(selected['candidate_id'],selected['workload_id'],hashlib.sha256(manifest.read_bytes()).hexdigest(),
            'https://integration-runtime-fixture.invalid','current-host-fixture','a'*64)
        planned=chunks.planned_lanes([site],classes,
            {'prior_slots':[],'modes':['tamaraw'],'maximum_visits':16},
            {'path':'/host-fixture-unpublished-chunk-policy','sha256':'b'*64},shard=batch['ordinal'])
        row={'candidate_id':selected['candidate_id'],'class_index':selected['class_index'],
            'workload_id':selected['workload_id'],'canonical_sites':selected['canonical_sites'],
            'original_graph_sha256':original_graph,'capture_limits':limits}
        # The final reader requires the immutable full class prefix. Class12
        # cannot be passed as a new class1, even in controlled mapping reports.
        all_rows=[]
        for member in classes[:-1]:
            input_ref=member.get('capture_input') or genuine_seed[2]['seed_inputs'][member['candidate_id']]
            original_ref=ledger.input_metadata(input_ref)[0]['original_manifest']
            original=json.loads(ledger.plain.reopen(original_ref).read_bytes())
            all_rows.append({'candidate_id':member['candidate_id'],'class_index':member['class_index'],
                'workload_id':member['workload_id'],'canonical_sites':member['canonical_sites'],
                'original_graph_sha256':hashlib.sha256(json.dumps(original['resources'],sort_keys=True,separators=(',',':')).encode()).hexdigest(),
                'capture_limits':member['capture_limits']})
        all_rows.append(row)
        # Controlled accepted reports are mapping fixtures, not original deep
        # closures. Their count can never publish a final scientific corpus.
        reports=[lane(row,'tamaraw',entry.slot_start,entry.visits_per_workload) for entry in planned]
        result=corpus.coverage(all_rows,reports,require_complete=False)
        assert result['accepted']==64 and result['scientific_credit'] is False
        assert len(reports)==4 and [entry.visits_per_workload for entry in planned]==[16]*4
        assert [sample['visit'] for report in reports for sample in report['samples']]==list(range(64))
        changed=copy.deepcopy(reports);changed[-1]['samples'][0]['visit']=0
        with pytest.raises(ValueError):corpus.coverage(all_rows,changed,require_complete=False)
        owner.check()
