from cbacert import cbacert
import os
import json
import base64
import time
import requests
import jwt

idp_private_key = os.getenv("IDP_PRIVATE_KEY")
if not idp_private_key:
    raise SystemExit()

client_id = "edge-security.int.prd.venafi-production"
cba_cert = cbacert(client_id, idp_private_key, prod=True)  # targetting non prod

csr = os.getenv("CF_CSR")

# issue certificate
post_body = {
    "subject": "autopoc1.evolveatcommbank.com.au",
    "csr": csr,
    "cadn": "ext",  # For internal cert do not use signer (cadn)
    "name": "autopoc1.evolveatcommbank.com.au - prod API client ",
    "san": {"TypeName": 2, "Name": "autopoc1.evolveatcommbank.com.au"} ,
    "tso": "CI023409481",  # Cloudflare CDN WAAP Prod
    # "tso": "CI023408291",  # Cloudflare CDN WAAP Non Prod
}
print(post_body)

# signed_cert = cba_cert.refresh(json.dumps(post_body))

# cert_data = signed_cert["certificatedata"]
# cert = base64.b64decode(cert_data).decode("utf-8")

scope = "cert-tso-list"


res = cba_cert.api("/tso/list", scope, get=True)
print(res)
