import json
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest

from adaptive_waf.contracts import HttpRequestRecord
from adaptive_waf.features.inspection import VERSION, inspection_group
from adaptive_waf.training.candidate_data import byte_tokens, field_tokens, load_role, sha256
from adaptive_waf.training.candidates import fit_torch, initialize_torch, CandidatePredictor
from scripts.candidate_experiments import CLASSES, fit, evaluate, preflight


def population(root):
    import adaptive_waf.features.inspection as representation
    directory = root/'protocol'
    directory.mkdir()
    manifest = {'representation':VERSION,'representation_source_sha256':sha256(representation.__file__),
                'group_ids':{},'counts':{},'sha256':{},'limitations':['Tiny synthetic regression fixture; no research accuracy claim.']}
    for role in ('train','tune','evaluation'):
        rows = []
        for index,label in enumerate(CLASSES):
            request = {'method':'GET','path':f'/{chr(97+index)}/{role}','query':'q=hello'}
            group = inspection_group(HttpRequestRecord(**request))
            rows.append({'request':request,'label':label,'group_id':group,'population':role})
        path = directory/(role+'.jsonl')
        path.write_text(''.join(json.dumps(row)+'\n' for row in rows),encoding='utf-8')
        manifest['group_ids'][role] = sorted(row['group_id'] for row in rows)
        manifest['counts'][role] = dict.fromkeys(CLASSES,1)
        manifest['sha256'][role] = sha256(path)
    (directory/'manifest.json').write_text(json.dumps(manifest),encoding='utf-8')
    return directory


class CandidateExperimentsTests(unittest.TestCase):
    def test_frozen_population_rejects_tampering_and_overlap(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = population(Path(temporary))
            self.assertEqual(len(load_role(directory,'train')[0]),6)
            with (directory/'train.jsonl').open('a',encoding='utf-8') as stream:
                stream.write('\n')
            with self.assertRaisesRegex(ValueError,'hash'):
                load_role(directory,'train')
            manifest = json.loads((directory/'manifest.json').read_text())
            manifest['group_ids']['evaluation'][0] = manifest['group_ids']['train'][0]
            (directory/'manifest.json').write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError,'overlap'):
                load_role(directory,'tune')

    def test_field_tokens_preserve_later_field_tail_and_unicode(self):
        request = HttpRequestRecord('POST','/x','x'*20000,cookies={'s':'y'*20000+'endcookie'},body='z'*20000+'endbody')
        values = field_tokens(request,lambda value:list(value.encode()),256,cls_id=1,sep_id=2,pad_id=0)
        self.assertEqual(len(values),256)
        self.assertIn(b'endcookie',bytes(values))
        self.assertIn(b'endbody',bytes(values))
        a = byte_tokens(HttpRequestRecord('GET','/','q=雪'))
        b = byte_tokens(HttpRequestRecord('GET','/','q=雨'))
        self.assertNotEqual(a,b)
        self.assertTrue(all(0 <= item < 259 for item in a))

    def test_checkpoint_resume_matches_uninterrupted_cpu_training(self):
        import torch
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            requests = [HttpRequestRecord('GET','/a'),HttpRequestRecord('GET','/b')]
            dataset = (requests,['BENIGN','XSS'])
            options = {'epochs':2,'batch_size':2,'max_length':64,'learning_rate':.01,
                       'embedding_dimension':4,'filters':2,'dropout':.2,'patience':2}
            full,part,resumed,bad = [root/name for name in ('full','part','resumed','bad')]
            for directory in (full,part,resumed,bad):directory.mkdir()
            a = fit_torch('byte_cnn',dataset,dataset,['BENIGN','XSS'],options,42,full,'frozen',device_name='cpu')
            fit_torch('byte_cnn',dataset,dataset,['BENIGN','XSS'],options,42,part,'frozen',device_name='cpu',stop_after_epoch=1)
            before = sha256(part/'last_checkpoint.pt')
            b = fit_torch('byte_cnn',dataset,dataset,['BENIGN','XSS'],options,42,resumed,'frozen',device_name='cpu',resume=part/'last_checkpoint.pt')
            self.assertEqual(a['history'],b['history'])
            x = torch.load(full/'model.pt',weights_only=True)['state_dict']
            y = torch.load(resumed/'model.pt',weights_only=True)['state_dict']
            self.assertTrue(all(torch.equal(x[key],y[key]) for key in x))
            self.assertEqual(before,sha256(part/'last_checkpoint.pt'))
            with self.assertRaisesRegex(ValueError,'mismatch'):
                fit_torch('byte_cnn',dataset,dataset,['BENIGN','XSS'],options,42,bad,'changed',device_name='cpu',resume=part/'last_checkpoint.pt')

    def test_classical_fit_reload_model_only_evaluation_and_integrity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = population(root)
            config = {'protocol':str(directory),'device':'cpu','candidates':{'lexical':{}},'seeds':[7],
                      'limits':{'wall_minutes':1,'rss_gib':1}}
            preflight(config)
            # Fitting must not inspect the evaluation payload. Corrupt it temporarily.
            final_bytes = (directory/'evaluation.jsonl').read_bytes()
            (directory/'evaluation.jsonl').write_bytes(b'quarantined')
            candidate = root/'lexical'
            fit(config,'lexical',7,candidate)
            (directory/'evaluation.jsonl').write_bytes(final_bytes)
            result = evaluate(config,candidate)
            self.assertFalse(result['rules_used'])
            self.assertEqual(result['fully_inspected_model_decisions'],6)
            self.assertEqual({row['group_id'] for row in result['samples']},set(load_role(directory,'evaluation')[3]))
            self.assertEqual(len(result['confusion_matrix']),6)
            (candidate/'model.joblib').write_bytes(b'corrupted')
            with self.assertRaisesRegex(ValueError,'content mismatch'):
                CandidatePredictor(candidate)

    def test_compact_initializes_two_base_layers_with_new_task_head(self):
        import torch
        from transformers import DistilBertConfig, DistilBertModel, BertTokenizerFast
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = DistilBertModel(DistilBertConfig(vocab_size=8,dim=12,hidden_dim=16,n_layers=3,n_heads=3))
            base.save_pretrained(root)
            (root/'vocab.txt').write_text('[PAD]\n[UNK]\n[CLS]\n[SEP]\n[MASK]\na\nb\nc\n')
            BertTokenizerFast(vocab_file=str(root/'vocab.txt')).save_pretrained(root)
            model,_ = initialize_torch('compact_transformer',{'pretrained_model':str(root)},CLASSES)
            self.assertEqual(model.config.n_layers,2)
            self.assertEqual(model.classifier.out_features,6)
            self.assertTrue(torch.equal(base.transformer.layer[1].ffn.lin1.weight,model.distilbert.transformer.layer[1].ffn.lin1.weight))

    def test_real_bounded_cli_completes_only_tiny_cpu_candidate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = population(root)
            config = root/'config.toml'
            config.write_text(f'protocol = {json.dumps(str(directory))}\ndevice = "cpu"\nseeds = [7]\n'
                              '[limits]\nwall_minutes = 1\nrss_gib = 2\n[candidates.structural]\n',encoding='utf-8')
            run = subprocess.run([sys.executable,'-m','scripts.candidate_experiments','--config',str(config),
                                  '--output',str(root/'experiment'),'--execute'],capture_output=True,text=True,timeout=50)
            self.assertEqual(run.returncode,0,run.stdout+run.stderr)
            outcomes = json.loads((root/'experiment/outcomes.json').read_text())
            self.assertEqual([item['phase'] for item in outcomes],['fit','evaluation'])
            self.assertTrue(all(item['exit_code'] == 0 for item in outcomes))
            self.assertTrue((root/'experiment/structural-7-evaluation.json').is_file())
