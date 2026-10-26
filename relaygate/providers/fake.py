from .base import SendResult,ProviderError,ProviderCapError

class FakeProvider:
    name="fake"
    def __init__(self,cost=0.01,drift=1.0):
        self.cost=cost; self.drift=drift; self.sent=[]; self.disabled=set(); self.opted_out=set(); self.scopes={}
    def provision_agent_scope(self,agent_id,daily_cap_usd):
        ref="fake_"+agent_id; self.scopes[ref]=daily_cap_usd; return ref
    def disable_agent_scope(self,ref): self.disabled.add(ref); return True
    def send(self,*,to,sender,body,ref):
        if ref in self.disabled: raise ProviderCapError(code=429)
        if to in self.opted_out: raise ProviderError(code="OPT_OUT")
        spent=sum(x["cost"] for x in self.sent if x["ref"]==ref)
        if spent+self.cost>self.scopes.get(ref,float("inf")): raise ProviderCapError(code=429)
        mid=f"msg_{len(self.sent)+1}"; self.sent.append({"id":mid,"to":to,"sender":sender,"body":body,"ref":ref,"cost":self.cost*self.drift}); return SendResult(mid)
    def usage(self,ref,since):
        return {"messages":[{"provider_msg_id":x["id"],"cost_usd":x["cost"]} for x in self.sent if x["ref"]==ref],"voice_usd":0}
