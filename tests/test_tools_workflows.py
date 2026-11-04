import copy,json,tempfile,unittest
import os
from unittest.mock import patch
from pathlib import Path
from adaptive_waf.adaptation.rl_training import train
from adaptive_waf.runtime.routing import LinUCB,RoutingContext
from adaptive_waf.runtime.replay import replay
from adaptive_waf.service.model_tools import query_models

def fixture():
    def row(i,role):
        return {'request_id':f'{role}-{i}','group_id':f'{role}/template-{i}','population':role,'label_source':'VERIFIED',
                'expected':'XSS' if i%2 else 'BENIGN','pre_action_context':{'fast_risk':.8 if i%2 else .05,'entropy':.8 if i%2 else .05,'margin':.1 if i%2 else .9},
                'outcomes':{'FAST_ONLY':{'predicted':'BENIGN','latency_ms':1,'compute_cost':.01},
                            'BOTH':{'predicted':'XSS' if i%2 else 'BENIGN','latency_ms':2,'compute_cost':.02}}}
    return {'review_reference':'CONTROLLED_SYNTHETIC_REGRESSION_ONLY','model_versions':{'fixture':'v1'},
            'development':[row(i,'development') for i in range(20)],'evaluation':[row(i,'evaluation') for i in range(10)]}

class OperatorToolsTests(unittest.TestCase):
    def test_offline_three_seed_training_serialization_and_evaluation(self):
        with tempfile.TemporaryDirectory() as temporary:
            report=train(fixture(),temporary)
            self.assertEqual(len(report['results']),6)
            self.assertFalse(report['automatic_promotion'])
            self.assertEqual(len(report['policy_artifacts']),6)
            for run in report['results']:
                if run['constrained']:
                    self.assertTrue(all(row['route']=='BOTH' for row in run['decisions'] if row['expected']=='XSS'))
            policies=json.loads((Path(temporary)/report['run_id']/'policies.json').read_text())
            for state in policies:
                restored=LinUCB.from_state(state['policy'])
                self.assertIn(restored.select(RoutingContext(.1,.1,.9),{'BOTH','FAST_ONLY'})[0],{'BOTH','FAST_ONLY'})
            for name in report['policy_artifacts']:
                state=json.loads((Path(temporary)/report['run_id']/name).read_text())
                LinUCB.from_state(state['policy'])
                self.assertEqual(state['model_versions'],fixture()['model_versions'])
            self.assertGreater(report['static_baselines']['BOTH'],report['static_baselines']['FAST_ONLY'])

    def test_rl_rejects_leakage_unreviewed_and_unknown_actions_without_artifacts(self):
        for corruption in ('overlap','label','action'):
            data=fixture()
            if corruption=='overlap':data['evaluation'][0]['group_id']=data['development'][0]['group_id']
            elif corruption=='label':data['development'][0]['label_source']='MODEL_PREDICTION'
            else:data['evaluation'][0]['outcomes']['INVALID']={'predicted':'BENIGN','latency_ms':0,'compute_cost':0}
            with tempfile.TemporaryDirectory() as temporary:
                with self.assertRaises(ValueError):train(data,temporary)
                self.assertFalse(list(Path(temporary).iterdir()))

    def test_replay_checks_deadline(self):
        with self.assertRaisesRegex(ValueError,'time budget'):replay(fixture()['development'],LinUCB(),deadline=0)

    def test_model_tools_do_not_accept_arbitrary_stages_or_paths(self):
        with self.assertRaises(ValueError):query_models({'stage':'../../file','requests':[]},None)
        with self.assertRaises(ValueError):query_models({'stage':'triage','algorithm':'../../model','requests':[]},None)

    def test_deep_query_uses_candidate_config_and_returns_model_scores(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);(root/'configs/models').mkdir(parents=True)
            (root/'configs/models/deep_deployment.toml').write_text('candidate="distilbert"\nartifact="fixture/model"\n')
            pipeline=SimpleNamespace(adjudicate=lambda request:(SimpleNamespace(class_scores={'BENIGN':.25,'XSS':.75}),1.))
            result=query_models({'stage':'deep','requests':[{'method':'GET','path':'/'}]},pipeline,root)
            self.assertEqual(result['algorithm'],'distilbert')
            self.assertEqual(result['results'][0]['prediction'],'XSS')
            self.assertFalse(result['rules_used'])

    def test_training_api_requires_service_auth_and_retains_shadow_artifacts(self):
        from fastapi.testclient import TestClient
        from adaptive_waf.adaptation.service import create_app,AdaptationSettings
        with tempfile.TemporaryDirectory() as temporary,patch.dict(os.environ,{'WAF_INTERNAL_TOKEN':'fixture-token'}):
            app=create_app(AdaptationSettings(curated_root=Path(temporary)/'curated'))
            with TestClient(app) as client:
                self.assertEqual(client.post('/internal/v1/tools/rl/validate').status_code,401)
                response=client.post('/internal/v1/tools/rl/validate',headers={'X-WAF-Internal-Token':'fixture-token'})
                self.assertEqual(response.status_code,200,response.text)
                self.assertEqual(response.json()['data_origin'],'CONTROLLED_SIMULATION')
                self.assertFalse(response.json()['automatic_promotion'])
                self.assertTrue((Path(temporary)/'routing'/response.json()['run_id']/'policies.json').exists())
