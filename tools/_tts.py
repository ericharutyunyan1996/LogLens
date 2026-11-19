"""Batch text-to-speech helper for tools/demo.py (runs inside the Piper venv: ~/.loglens-demo/tts-venv).

python _tts.py voice.onnx texts.json outdir      # texts.json: {"name": "spoken text", ...} -> outdir/name.wav
"""

import json
import sys
import wave
from pathlib import Path

from piper import PiperVoice, SynthesisConfig

voice_path, texts_path, out = sys.argv[1], sys.argv[2], Path(sys.argv[3])
out.mkdir(parents=True, exist_ok=True)
voice = PiperVoice.load(voice_path)
# a lively delivery: slightly faster, more pitch/energy variation than the flat default
config = SynthesisConfig(length_scale=0.9, noise_scale=0.85, noise_w_scale=0.9)
for name, text in json.loads(Path(texts_path).read_text(encoding="utf-8")).items():
    with wave.open(str(out / f"{name}.wav"), "wb") as wav:
        voice.synthesize_wav(text, wav, syn_config=config)
print("done")
