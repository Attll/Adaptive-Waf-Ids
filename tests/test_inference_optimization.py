import unittest
from unittest.mock import Mock,patch
from types import SimpleNamespace
from pathlib import Path
import tempfile
from sklearn.ensemble import RandomForestClassifier
from adaptive_waf.runtime.optimization import configure_inference_threads
from adaptive_waf.runtime.artifacts import DistilBertPredictor
from adaptive_waf.contracts import HttpRequestRecord,AttackClass


class InferenceOptimizationTests(unittest.TestCase):
    def test_injected_cuda_oom_recovers_on_cpu_without_exhausting_real_vram(self):
        import torch
        class Input:
            def to(self,device): return torch.tensor([[1]])
        class Model:
            config=SimpleNamespace(id2label={0:"BENIGN",1:"XSS"})
            calls=0
            def __call__(self,**kwargs):
                self.calls+=1
                if self.calls==1: raise torch.OutOfMemoryError("injected CUDA allocation failure")
                return SimpleNamespace(logits=torch.tensor([[2.,1.]]))
            def to(self,device): self.device=device; return self
        with tempfile.TemporaryDirectory() as directory:
            temperature=Path(directory)/"temperature.json"
            temperature.write_text('{"temperature":1.0}')
            predictor=DistilBertPredictor(Path(directory),temperature,"cuda")
            model=Model()
            facade=SimpleNamespace(OutOfMemoryError=torch.OutOfMemoryError,inference_mode=torch.inference_mode,softmax=torch.softmax,
                cuda=SimpleNamespace(empty_cache=Mock()))
            with patch.object(predictor,"_loaded",return_value=(facade,model,lambda *args,**kwargs:{"input":Input()},torch.device("cuda"))):
                scores=predictor(HttpRequestRecord("GET","/health"))
            self.assertEqual(predictor._device_name,"cpu")
            self.assertEqual(model.calls,2)
            self.assertEqual(max(scores,key=scores.get),AttackClass.BENIGN)
            self.assertEqual(predictor.last_device_fallback,"CUDA_OUT_OF_MEMORY")

    def test_thread_control_preserves_predictions(self):
        model = RandomForestClassifier(n_estimators=8,random_state=641,n_jobs=2).fit([[0],[1],[2],[3]],[0,0,1,1])
        before = model.predict_proba([[1.5]])
        configure_inference_threads(model,1)
        self.assertEqual(model.n_jobs,1)
        self.assertTrue((before == model.predict_proba([[1.5]])).all())
        with self.assertRaises(ValueError):
            configure_inference_threads(model,0)
