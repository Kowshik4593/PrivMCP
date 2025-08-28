import inspect

def safe_charge(accountant, **kwargs):
    """
    Call accountant.charge with only the kwargs it supports.
    Falls back to positional (epsilon, sensitivity) if needed.
    """
    if not hasattr(accountant, "charge"):
        raise AttributeError("accountant missing .charge()")

    try:
        sig = inspect.signature(accountant.charge)
        supported = {k: v for k, v in kwargs.items() if k in sig.parameters}
        return accountant.charge(**supported)
    except TypeError:
        # minimal fallback for legacy implementations: (epsilon, sensitivity)
        return accountant.charge(kwargs.get("epsilon"), kwargs.get("sensitivity"))
