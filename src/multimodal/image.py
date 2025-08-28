from transformers import Blip2Processor, Blip2ForConditionalGeneration
from PIL import Image

_blip_model = None
_blip_processor = None

def get_blip():
    global _blip_model, _blip_processor
    if _blip_model is None or _blip_processor is None:
        _blip_processor = Blip2Processor.from_pretrained("Salesforce/blip2-opt-2.7b")
        _blip_model = Blip2ForConditionalGeneration.from_pretrained("Salesforce/blip2-opt-2.7b")
    return _blip_model, _blip_processor

def image_to_text(image_path):
    try:
        model, processor = get_blip()
        img = Image.open(image_path)
        prompt = "Describe this x-ray image in clinical terms.\n"
        inputs = processor(img, prompt, return_tensors="pt")
        output = model.generate(**inputs)
        caption = processor.decode(output[0], skip_special_tokens=True)
        # Clean up temp file
        try:
            import os
            os.remove(image_path)
        except Exception:
            pass
        return f"[BLIP2: {caption}]"
    except Exception as e:
        return "[Image error: " + str(e) + "]"
