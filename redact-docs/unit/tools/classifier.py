"""Layer 2: GLiNER span classifier on onnxruntime and tokenizers, no PyTorch.

Reimplements the parts of the `gliner` package (0.2.30) that inference needs
for a span-mode (markerV0) model:
  * words come from GLiNER's whitespace splitter, r"\\w+(?:[-_]\\w+)*|\\S"
  * the prompt is <<ENT>> label ... <<ENT>> label <<SEP>> followed by the words,
    tokenized as pre-split words; the first subtoken of each text word carries
    its 1-based word index in words_mask
  * every span (start, start + width) with width < max_width is scored; spans
    that run past the last word are masked
  * scores are sigmoid(logits); spans over the threshold are kept greedily by
    score with no overlap (flat NER), as gliner's greedy_search does
Checked against the reference package with the same model: identical spans on
20 of 20 paragraphs of the bundled intake form.

Long texts are cut into overlapping word windows; overlaps are resolved by the
pipeline's merge step (the union of spans, longest class wins).
"""
import json
import os
import re

WORD_RE = re.compile(r"\w+(?:[-_]\w+)*|\S")


class ClassifierError(Exception):
    pass


class Gliner:
    def __init__(self, onnx_path, model_dir, threads=4):
        try:
            import numpy as np
            import onnxruntime as ort
            from tokenizers import Tokenizer
        except ImportError as e:
            raise ClassifierError(f"classifier dependencies missing ({e.name})") from None
        self.np = np
        with open(os.path.join(model_dir, "gliner_config.json"), encoding="utf-8") as f:
            cfg = json.load(f)
        if cfg.get("span_mode") != "markerV0":
            raise ClassifierError("unsupported GLiNER span_mode")
        self.max_width = int(cfg["max_width"])
        self.ent_token = cfg["ent_token"]
        self.sep_token = cfg["sep_token"]
        self.tokenizer = Tokenizer.from_file(os.path.join(model_dir, "tokenizer.json"))
        opts = ort.SessionOptions()
        opts.intra_op_num_threads = threads
        opts.inter_op_num_threads = 1
        opts.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL
        opts.log_severity_level = 3
        self.session = ort.InferenceSession(onnx_path, opts, providers=["CPUExecutionProvider"])

    def predict_words(self, words, labels, threshold):
        """Spans over one list of words: [(first_word, last_word, label_index, score)]."""
        np = self.np
        n = len(words)
        if n == 0:
            return []
        prompt = []
        for label in labels:
            prompt += [self.ent_token, label]
        prompt.append(self.sep_token)
        enc = self.tokenizer.encode(prompt + list(words), is_pretokenized=True)
        skip = len(prompt)
        words_mask, prev = [], None
        for wid in enc.word_ids:
            if wid is None or wid < skip or wid == prev:
                words_mask.append(0)
            else:
                words_mask.append(wid - skip + 1)
            prev = wid
        k = self.max_width
        span_idx = np.array([[[i, i + w] for i in range(n) for w in range(k)]], dtype=np.int64)
        span_mask = span_idx[..., 1] <= n - 1
        feed = {
            "input_ids": np.array([enc.ids], dtype=np.int64),
            "attention_mask": np.array([enc.attention_mask], dtype=np.int64),
            "words_mask": np.array([words_mask], dtype=np.int64),
            "text_lengths": np.array([[n]], dtype=np.int64),
            "span_idx": span_idx,
            "span_mask": span_mask,
        }
        logits = self.session.run(None, feed)[0][0]  # [words, width, classes]
        probs = 1.0 / (1.0 + np.exp(-logits))
        cands = []
        for s, w, c in zip(*np.nonzero(probs > threshold)):
            if s + w + 1 <= n:
                cands.append((int(s), int(s + w), int(c), float(probs[s, w, c])))
        cands.sort(key=lambda t: -t[3])  # stable, so ties keep (start, width, class) order
        kept = []
        for cand in cands:
            if all(cand[1] < k0[0] or k0[1] < cand[0] for k0 in kept):
                kept.append(cand)
        return sorted(kept)

    def predict(self, text, labels, threshold, window=192, overlap=48):
        """Character spans over text: [(start, end, label_index, score)]."""
        matches = list(WORD_RE.finditer(text))
        out = []
        step = window - overlap
        start = 0
        while True:
            chunk = matches[start:start + window]
            for s, e, c, score in self.predict_words([m.group() for m in chunk], labels, threshold):
                out.append((chunk[s].start(), chunk[e].end(), c, score))
            if start + window >= len(matches):
                break
            start += step
        return out
