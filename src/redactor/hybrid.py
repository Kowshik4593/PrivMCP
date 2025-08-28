# src/redactor/hybrid.py
import re
from typing import Dict, List, Optional

import torch
from transformers import AutoTokenizer, AutoModelForTokenClassification
from transformers.utils import logging as hf_logging

try:
    import medspacy
except Exception:  # medspacy is optional for import-time safety
    medspacy = None


class HybridPHIRedactor:
    """
    Hybrid PHI redactor:
      - Optional transformer NER (lazy + offline safe)
      - medSpaCy (rule/target-based)
      - Strong regex fallback for common identifiers (SSN, MRN, email, phone, names)
    """

    def __init__(
        self,
        use_transformer: bool = False,
        transformer_model: str = "dslim/bert-base-NER",
    ):
        # --- runtime toggles ---
        self._use_transformer_flag = bool(use_transformer)
        self._transformer_model_name = transformer_model

        # --- lazy HF model handles (not loaded until needed) ---
        self._transformer_ready = False
        self.tokenizer: Optional[AutoTokenizer] = None
        self.model: Optional[AutoModelForTokenClassification] = None

        # --- medSpaCy pipeline (lightweight rules; loads locally) ---
        # medspaCy does not require external downloads for basic pipeline.
        if medspacy is not None:
            try:
                self.nlp = medspacy.load()
            except Exception:
                self.nlp = None
        else:
            self.nlp = None

        # --- compiled regex patterns as offline fallback ---
        self._regex_patterns = {
            "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
            "MRN": re.compile(r"\bMRN[:\s]*[A-Za-z0-9-]+\b", re.IGNORECASE),
            "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
            "PHONE": re.compile(
                r"\b(?:\+?1[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}\b"
            ),
            # Simple name heuristic when preceded by "Patient "
            "PATIENT_NAME": re.compile(r"\bPatient\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})\b"),
        }

        # Drop very short or noisy entities like "MR", "Pub", "ed"
        self._entity_stop = {"mr", "pub", "ed", "rn", "ss", "n"}

    # ----------------------------
    # Lazy init helper for HF NER
    # ----------------------------
    def _ensure_transformer_loaded(self) -> None:
        """Load the HF model only once, and never hit the network if offline."""
        if self._transformer_ready or not self._use_transformer_flag:
            return
        try:
            tok, mdl = self._load_transformer(
                model_path=None if not getattr(self, "_transformer_model_name", None) else None,
                model_id=self._transformer_model_name,
                offline=getattr(self, "_use_transformer_flag", True) and True,
            )
            if tok and mdl:
                self.tokenizer = tok
                self.model = mdl
                self.model.eval()
                self._transformer_ready = True
            else:
                # fallback
                self._use_transformer_flag = False
                self._transformer_ready = False
                self.tokenizer = None
                self.model = None
        except Exception:
            self._use_transformer_flag = False
            self._transformer_ready = False
            self.tokenizer = None
            self.model = None

    def _load_transformer(self, model_path: Optional[str], model_id: str, offline: bool):
        """Load tokenizer and model with optional offline-only mode and graceful fallback.

        model_path: optional local dir path or None to use model_id
        model_id: HF repo id
        offline: if True, pass local_files_only=True to HF loaders
        Returns (tokenizer, model) or (None, None) on failure.
        """
        hf_logging.set_verbosity_error()
        kw = {"local_files_only": bool(offline)}
        try:
            if model_path:
                tok = AutoTokenizer.from_pretrained(model_path, **kw)
                mdl = AutoModelForTokenClassification.from_pretrained(model_path, **kw)
            else:
                tok = AutoTokenizer.from_pretrained(model_id, **kw)
                mdl = AutoModelForTokenClassification.from_pretrained(model_id, **kw)
            return tok, mdl
        except Exception as e:
            try:
                # log and fallback
                import logging

                logging.getLogger(__name__).exception("PHI transformer unavailable; falling back to regex-only. Reason: %s", e)
            except Exception:
                pass
            return None, None

    # ----------------------------
    # Transformer NER
    # ----------------------------
    def bert_ner(self, text: str, chunk_size: int = 384, overlap: int = 48) -> List[str]:
        """Runs BERT NER in overlapping chunks; returns merged entity list. Offline-safe."""
        if not self._use_transformer_flag:
            return []

        self._ensure_transformer_loaded()
        if not self._transformer_ready or self.tokenizer is None or self.model is None:
            return []

        words = text.split()
        n = len(words)
        i = 0
        found = set()

        while i < n:
            chunk = " ".join(words[i : i + chunk_size])
            tokens = self.tokenizer(
                chunk,
                return_tensors="pt",
                truncation=True,
                max_length=chunk_size,
                padding="max_length",
            )
            with torch.no_grad():
                outputs = self.model(**tokens).logits
            predictions = torch.argmax(outputs, dim=2)
            tokens_list = self.tokenizer.convert_ids_to_tokens(tokens["input_ids"][0])

            # Extract BIO spans and merge WordPieces properly
            current = []
            for idx, pred in enumerate(predictions[0]):
                token = tokens_list[idx]
                if token in {"[CLS]", "[SEP]", "[PAD]"}:
                    continue
                label = self.model.config.id2label[pred.item()]
                if label.startswith("B-"):
                    if current:
                        found.add(self._merge_wordpieces(current))
                    current = [token]
                elif label.startswith("I-") and current:
                    current.append(token)
                else:
                    if current:
                        found.add(self._merge_wordpieces(current))
                        current = []
            if current:
                found.add(self._merge_wordpieces(current))

            i += max(1, chunk_size - overlap)

        # Filter noisy/short entities
        cleaned = [self._normalize_entity(e) for e in found]
        cleaned = [e for e in cleaned if self._keep_entity(e)]
        return list(dict.fromkeys(cleaned))  # preserve first-seen order

    @staticmethod
    def _merge_wordpieces(pieces: List[str]) -> str:
        """
        Merge BERT wordpieces: ["John", "Do", "##e"] -> "John Doe"
        """
        words: List[str] = []
        for p in pieces:
            if p.startswith("##"):
                if words:
                    words[-1] = words[-1] + p[2:]
                else:
                    words.append(p[2:])
            else:
                # normalize "##" inside token if any (rare)
                p = p.replace("##", "")
                # restore spacing correctly
                if p == "##":
                    continue
                words.append(p)
        return " ".join(words).strip()

    @staticmethod
    def _normalize_entity(e: str) -> str:
        return re.sub(r"\s+", " ", e).strip()

    def _keep_entity(self, e: str) -> bool:
        if not e:
            return False
        # drop very short tokens unless they contain digits (e.g., "A1")
        if len(e) < 3 and not any(ch.isdigit() for ch in e):
            return False
        if e.lower() in self._entity_stop:
            return False
        return True

    # ----------------------------
    # medSpaCy NER (rule-based)
    # ----------------------------
    def medspacy_ner(self, text: str) -> List[str]:
        if not self.nlp:
            return []
        doc = self.nlp(text)
        ents = [ent.text for ent in doc.ents]
        # normalize and filter
        out = []
        for e in ents:
            e = self._normalize_entity(e)
            if self._keep_entity(e):
                out.append(e)
        return out

    # ----------------------------
    # Regex fallback NER
    # ----------------------------
    def regex_ner(self, text: str) -> List[str]:
        found: List[str] = []
        for key, pat in self._regex_patterns.items():
            if key == "PATIENT_NAME":
                for m in pat.finditer(text):
                    name = m.group(1)
                    name = self._normalize_entity(name)
                    if self._keep_entity(name):
                        found.append(name)
            else:
                for m in pat.finditer(text):
                    val = self._normalize_entity(m.group(0))
                    if self._keep_entity(val):
                        found.append(val)
        # Deduplicate preserving order
        return list(dict.fromkeys(found))

    # ----------------------------
    # Redaction
    # ----------------------------
    def redact(self, text: str) -> Dict:
        # Collect entities
        ents = set()
        for src in (self.regex_ner(text), self.medspacy_ner(text), self.bert_ner(text)):
            ents.update(src)

        # Sort longest-first to avoid partial overlaps
        sorted_ents = sorted(ents, key=len, reverse=True)

        redacted = text
        for ent in sorted_ents:
            if not ent.strip():
                continue

            # Build a safe pattern with word boundaries for alphabetic tokens.
            # For alnum/IDs, require non-word boundaries and ignore spacing variance.
            ent_escaped = re.escape(ent)
            if any(ch.isdigit() for ch in ent):
                # allow flexible whitespace inside (e.g., "MRN  123-45-6789")
                ent_escaped = ent_escaped.replace(r"\ ", r"\s+")
                pattern = re.compile(rf"(?<!\w){ent_escaped}(?!\w)", re.IGNORECASE)
            else:
                # pure words -> whole-word match
                # If the entity contains spaces, enforce word boundaries at ends.
                ent_escaped = ent_escaped.replace(r"\ ", r"\s+")
                pattern = re.compile(rf"\b{ent_escaped}\b", re.IGNORECASE)

            redacted = pattern.sub("[REDACTED]", redacted)

        return {
            "redacted_text": redacted,
            "phi_entities": list(sorted_ents),
        }
