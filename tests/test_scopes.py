import asyncio, base64, hashlib, json, re, secrets, sys
import httpx
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

BASE="http://127.0.0.1:8848"; RES="http://localhost:8848/mcp"; RD="https://claude.ai/api/mcp/auth_callback"
def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def body(r):
    d=getattr(r,"data",None)
    return d if d is not None else json.loads(r.content[0].text)

def get_token(scope):
    c=httpx.Client(follow_redirects=False,timeout=20)
    cid=c.post(f"{BASE}/oauth/register",json={"client_name":"scoped","redirect_uris":[RD]}).json()["client_id"]
    v=secrets.token_urlsafe(48); ch=b64u(hashlib.sha256(v.encode()).digest())
    p=dict(response_type="code",client_id=cid,redirect_uri=RD,state="s",
           code_challenge=ch,code_challenge_method="S256",scope=scope,resource=RES)
    r=c.post(f"{BASE}/oauth/login",data={**p,"username":"eric","password":"correct-horse-battery"})
    ck=r.headers["set-cookie"].split(";")[0]
    form={**p,"_action":"approve",**{f"scope_{s}":"on" for s in scope.split()}}
    r=c.post(f"{BASE}/oauth/authorize",data=form,headers={"cookie":ck})
    code=re.search(r"[?&]code=([^&]+)",r.headers["location"]).group(1)
    return c.post(f"{BASE}/oauth/token",data=dict(grant_type="authorization_code",code=code,
        client_id=cid,redirect_uri=RD,code_verifier=v,resource=RES)).json()["access_token"]

async def main():
    tok=get_token("fleet.read")
    async with Client(StreamableHttpTransport(f"{BASE}/mcp",headers={"Authorization":f"Bearer {tok}"})) as c:
        r=body(await c.call_tool("list_hosts",{}))
        assert r["your_scopes"]==["fleet.read"], r["your_scopes"]
        print("read-only token scopes =", r["your_scopes"])
        for tool,args in [("exec",{"host":"lab-1","command":"id"}),
                          ("write_file",{"host":"lab-1","path":"/tmp/x","content":"y"}),
                          ("tunnel_open",{"host":"lab-1","remote_port":22}),
                          ("audit_tail",{})]:
            try:
                await c.call_tool(tool,args); raise SystemExit(f"{tool} was not blocked")
            except Exception as e:
                assert "lacks" in str(e), (tool,e)
                print(f"  ok  {tool} denied: {str(e).strip().splitlines()[0][:60]}")
        r=body(await c.call_tool("read_file",{"host":"lab-1","path":"/etc/hostname"}))
        print("  ok  read_file still works ->", r["content"].strip())

    # no token / forged token
    async with httpx.AsyncClient() as h:
        r=await h.post(f"{BASE}/mcp",json={"jsonrpc":"2.0","id":1,"method":"initialize"})
        assert r.status_code==401 and "resource_metadata" in r.headers.get("www-authenticate","")
        print("no token -> 401 + WWW-Authenticate")
        bad=tok[:-6]+"AAAAAA"
        r=await h.post(f"{BASE}/mcp",json={"jsonrpc":"2.0","id":1,"method":"initialize"},
                       headers={"Authorization":f"Bearer {bad}"})
        assert r.status_code==401, r.status_code
        print("tampered signature -> 401")
        import jwt as pyjwt, time
        forged=pyjwt.encode({"iss":"http://localhost:8848","sub":"eric",
            "aud":"https://other.example/mcp","scope":"fleet.admin",
            "exp":int(time.time())+300},"x",algorithm="HS256")
        r=await h.post(f"{BASE}/mcp",json={"jsonrpc":"2.0","id":1,"method":"initialize"},
                       headers={"Authorization":f"Bearer {forged}"})
        assert r.status_code==401, r.status_code
        print("forged audience + HS256 -> 401")
    print("\nscope and token checks passed")

asyncio.run(main())
