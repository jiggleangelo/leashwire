from dataclasses import dataclass

@dataclass
class SendResult:
    provider_msg_id: str

class ProviderError(Exception):
    def __init__(self,message="provider error",code=None): super().__init__(message); self.code=str(code) if code is not None else None

class ProviderCapError(ProviderError): pass
