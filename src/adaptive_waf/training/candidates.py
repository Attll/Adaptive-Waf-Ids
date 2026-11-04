"""New model-only candidates. No security rules, active model reload or network downloads."""
import copy
import json
import os
from pathlib import Path
import random
from time import perf_counter

import joblib
import numpy as np

from adaptive_waf.training.candidate_data import byte_tokens, field_tokens, lexical_inputs, structural_inputs
from adaptive_waf.training.deep_training import _build_char_cnn, _resolve_device, _seed


def classical_candidate(name, seed):
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import FunctionTransformer, StandardScaler
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    classifier = LogisticRegression(C=1, class_weight='balanced', max_iter=300, random_state=seed)
    if name == 'lexical':
        return Pipeline([('view', FunctionTransformer(lexical_inputs)),
                         ('ngrams', TfidfVectorizer(analyzer='char', ngram_range=(3,5), max_features=50000,
                                                   min_df=1, sublinear_tf=True)), ('model', classifier)])
    if name == 'structural':
        return Pipeline([('view', FunctionTransformer(structural_inputs)), ('scale', StandardScaler()), ('model', classifier)])
    raise ValueError('unknown classical candidate')


def initialize_torch(name, options, classes):
    import torch
    if name == 'byte_cnn':
        return _build_char_cnn(torch, 259, len(classes), options), None
    if name not in {'compact_transformer', 'full_transformer'}:
        raise ValueError('unknown deep candidate')
    from transformers import AutoTokenizer, DistilBertConfig, DistilBertForSequenceClassification, DistilBertModel
    source = options['pretrained_model']
    tokenizer = AutoTokenizer.from_pretrained(source, local_files_only=True)
    base_config = DistilBertConfig.from_pretrained(source, local_files_only=True)
    # Always use the pristine cached language-model base, never old task-fitted weights.
    if base_config.architectures and any('SequenceClassification' in item for item in base_config.architectures):
        raise ValueError('candidate initialization must use an unfitted language-model base')
    base = DistilBertModel.from_pretrained(source, local_files_only=True)
    config = copy.deepcopy(base_config)
    config.n_layers = 2 if name == 'compact_transformer' else base_config.n_layers
    config.num_labels = len(classes)
    config.id2label = dict(enumerate(classes))
    config.label2id = {label:index for index,label in enumerate(classes)}
    model = DistilBertForSequenceClassification(config)
    state = {key:value for key,value in base.state_dict().items()
             if not key.startswith('transformer.layer.') or int(key.split('.')[2]) < config.n_layers}
    model.distilbert.load_state_dict(state, strict=True)
    return model, tokenizer


def encode_requests(requests, tokenizer, max_length):
    if tokenizer is None:
        return [byte_tokens(request, max_length) for request in requests]
    return [field_tokens(request, lambda text: tokenizer.encode(text, add_special_tokens=False), max_length,
                         cls_id=tokenizer.cls_token_id, sep_id=tokenizer.sep_token_id, pad_id=tokenizer.pad_token_id)
            for request in requests]


def logits_for(model, tokenizer, inputs):
    return model(inputs) if tokenizer is None else model(input_ids=inputs, attention_mask=(inputs != tokenizer.pad_token_id)).logits


def torch_probabilities(model, tokenizer, encoded, batch_size, device):
    import torch
    rows = []
    model.eval()
    with torch.inference_mode():
        for start in range(0, len(encoded), batch_size):
            batch = torch.tensor(encoded[start:start+batch_size], dtype=torch.long, device=device)
            rows.extend(torch.softmax(logits_for(model, tokenizer, batch), dim=1).cpu().tolist())
    return rows


def _atomic_checkpoint(torch, value, target):
    temporary = target.with_suffix('.tmp')
    torch.save(value, temporary)
    os.replace(temporary, target)


def fit_torch(name, train, tune, classes, options, seed, directory, signature, device_name='auto', resume=None,
              stop_after_epoch=None):
    """Epoch-boundary resume, including RNG/scaler/optimizer/best selection state.

    An interrupted batch is never resumed. Resume starts from the last complete
    epoch into a NEW directory; the parent candidate and checkpoints are read-only.
    stop_after_epoch is for tiny interruption regression fixtures.
    """
    import torch
    _seed(torch, seed)
    torch.set_num_threads(2)
    device = _resolve_device(torch, device_name)
    if device.type == 'cuda':
        torch.cuda.set_per_process_memory_fraction(float(options.get('gpu_memory_fraction', .5)), device)
        torch.cuda.reset_peak_memory_stats(device)
    model, tokenizer = initialize_torch(name, options, classes)
    model = model.to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=float(options['learning_rate']))
    scaler = torch.amp.GradScaler('cuda', enabled=device.type == 'cuda')
    class_ids = {label:index for index,label in enumerate(classes)}
    train_requests, train_labels = train
    tune_requests, tune_labels = tune
    train_encoded = encode_requests(train_requests, tokenizer, options['max_length'])
    tune_encoded = encode_requests(tune_requests, tokenizer, options['max_length'])
    counts = np.array([train_labels.count(label) for label in classes], dtype=float)
    if np.any(counts == 0):
        raise ValueError('every class needs training data')
    weights = np.minimum(20, len(train_labels)/(len(classes)*counts))
    loss_function = torch.nn.CrossEntropyLoss(weight=torch.tensor(weights, dtype=torch.float32, device=device))
    dataset = torch.utils.data.TensorDataset(torch.tensor(train_encoded, dtype=torch.long),
                  torch.tensor([class_ids[label] for label in train_labels], dtype=torch.long))
    history, best_loss, stale, start, best_state = [], float('inf'), 0, 1, None
    if resume:
        state = torch.load(resume, map_location='cpu', weights_only=True)
        if state['signature'] != signature or state['schema'] != 1:
            raise ValueError('resume configuration/population/source mismatch')
        if state['device_type'] != device.type:
            raise ValueError('resume device type differs; start a separately identified CPU run')
        model.load_state_dict(state['model'])
        optimizer.load_state_dict(state['optimizer'])
        scaler.load_state_dict(state['scaler'])
        history, best_loss, stale = state['history'], state['best_loss'], state['stale']
        start, best_state = state['epoch']+1, state['best_model']
        random.setstate(state['python_rng'])
        numpy_state = state['numpy_rng']
        np.random.set_state((numpy_state[0], np.array(numpy_state[1],dtype='uint32'), *numpy_state[2:]))
        torch.set_rng_state(state['torch_rng'])
        if device.type == 'cuda':
            torch.cuda.set_rng_state_all(state['cuda_rng'])
    begun = perf_counter()
    for epoch in range(start, options['epochs']+1):
        if stale >= options.get('patience', 2):
            break
        generator = torch.Generator().manual_seed(seed+epoch)
        loader = torch.utils.data.DataLoader(dataset, batch_size=options['batch_size'], shuffle=True,
                    generator=generator, num_workers=0, pin_memory=device.type == 'cuda')
        model.train()
        for inputs, targets in loader:
            optimizer.zero_grad(set_to_none=True)
            inputs = inputs.to(device, non_blocking=device.type == 'cuda')
            targets = targets.to(device, non_blocking=device.type == 'cuda')
            with torch.autocast(device_type=device.type, enabled=device.type == 'cuda'):
                loss = loss_function(logits_for(model, tokenizer, inputs), targets)
            scaler.scale(loss).backward()
            scaler.unscale_(optimizer)
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1)
            scaler.step(optimizer)
            scaler.update()
        probabilities = torch_probabilities(model, tokenizer, tune_encoded, options['batch_size'], device)
        validation_loss = -float(np.mean([np.log(max(row[class_ids[label]], 1e-12))
                                         for row,label in zip(probabilities,tune_labels,strict=True)]))
        history.append({'epoch':epoch, 'tune_log_loss':validation_loss})
        if validation_loss < best_loss:
            best_loss, stale = validation_loss, 0
            best_state = {key:value.detach().cpu().clone() for key,value in model.state_dict().items()}
        else:
            stale += 1
        checkpoint = {'schema':1, 'signature':signature, 'device_type':device.type, 'epoch':epoch,
                      'model':model.state_dict(), 'optimizer':optimizer.state_dict(), 'scaler':scaler.state_dict(),
                      'best_model':best_state, 'best_loss':best_loss, 'stale':stale, 'history':history,
                      'python_rng':random.getstate(), 'torch_rng':torch.get_rng_state(),
                      'numpy_rng':(np.random.get_state()[0],np.random.get_state()[1].tolist(),*np.random.get_state()[2:]),
                      'cuda_rng':torch.cuda.get_rng_state_all() if device.type == 'cuda' else []}
        _atomic_checkpoint(torch, checkpoint, directory/'last_checkpoint.pt')
        print(json.dumps(history[-1]), flush=True)
        if stop_after_epoch and epoch >= stop_after_epoch:
            return {'interrupted_after_complete_epoch':epoch}
    if best_state is None:
        raise ValueError('no completed checkpoint available')
    model.load_state_dict(best_state)
    torch.save({'state_dict':best_state}, directory/'model.pt')
    if tokenizer is not None:
        model.config.save_pretrained(directory/'model_config')
        tokenizer.save_pretrained(directory/'tokenizer')
    return {'device':str(device), 'mixed_precision':device.type == 'cuda', 'history':history,
            'fit_seconds':perf_counter()-begun, 'peak_allocated_bytes':torch.cuda.max_memory_allocated(device) if device.type == 'cuda' else 0,
            'peak_reserved_bytes':torch.cuda.max_memory_reserved(device) if device.type == 'cuda' else 0,
            'torch':str(torch.__version__), 'cuda_runtime':torch.version.cuda, 'resume_parent':str(resume) if resume else None}


class CandidatePredictor:
    """Model-only offline adapter; loading does not activate a gateway model."""
    def __init__(self, directory, device_name='cpu'):
        from adaptive_waf.training.candidate_data import sha256
        self.directory = Path(directory)
        self.manifest = json.loads((self.directory/'candidate.json').read_text(encoding='utf-8'))
        for name,digest in self.manifest['source_sha256'].items():
            if sha256(name) != digest:
                raise ValueError('candidate source representation mismatch')
        for name,digest in self.manifest['artifacts'].items():
            path = (self.directory/name).resolve()
            if not path.is_relative_to(self.directory.resolve()) or sha256(path) != digest:
                raise ValueError('candidate artifact content mismatch')
        self.classes = self.manifest['classes']
        self.name = self.manifest['candidate']
        self.tokenizer = None
        if self.name in {'structural','lexical'}:
            self.model = joblib.load(self.directory/'model.joblib')
        else:
            import torch
            self.device = _resolve_device(torch, device_name)
            if self.name == 'byte_cnn':
                self.model = _build_char_cnn(torch, 259, len(self.classes), self.manifest['options'])
            else:
                from transformers import AutoTokenizer, DistilBertConfig, DistilBertForSequenceClassification
                self.tokenizer = AutoTokenizer.from_pretrained(self.directory/'tokenizer', local_files_only=True)
                self.model = DistilBertForSequenceClassification(DistilBertConfig.from_pretrained(self.directory/'model_config', local_files_only=True))
            self.model.load_state_dict(torch.load(self.directory/'model.pt', map_location='cpu', weights_only=True)['state_dict'])
            self.model.to(self.device).eval()

    def predict_many(self, requests):
        if not requests:
            return []
        if self.name in {'structural','lexical'}:
            rows = self.model.predict_proba(requests)
            order = list(self.model.classes_)
            return [[float(row[order.index(label)]) for label in self.classes] for row in rows]
        encoded = encode_requests(requests, self.tokenizer, self.manifest['options']['max_length'])
        return torch_probabilities(self.model, self.tokenizer, encoded, self.manifest['options']['batch_size'], self.device)
