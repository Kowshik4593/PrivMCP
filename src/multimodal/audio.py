import whisper
import threading

_whisper_model = None
_whisper_lock = threading.Lock()

def get_whisper():
    global _whisper_model
    with _whisper_lock:
        if _whisper_model is None:
            _whisper_model = whisper.load_model("base")
    return _whisper_model

def audio_to_text(audio_path):
    try:
        model = get_whisper()
        result = model.transcribe(audio_path)
        # Clean up temp file
        try:
            import os
            os.remove(audio_path)
        except Exception:
            pass
        return result["text"].strip()
    except Exception as e:
        return "[Audio error: " + str(e) + "]"
