import base64
import hashlib
import os
import re
import json
import requests
from requests.auth import AuthBase, HTTPBasicAuth
from requests_oauthlib import OAuth2Session

# 認証準備
client_id = "VkxqTjJZem1ZWkx5a2l4angzV1E6MTpjaQ"
client_secret = "-aRQ0JaMxc7kb1oFdIT1ClrxQBMOuPZ8vPjhNKa01_rg0jCD5G"
redirect_uri = "http://localhost:3000/twitter/redirect"
scopes = ["tweet.read", "tweet.write", "users.read", \
        "offline.access", "list.read", "like.read", "like.write"] 
# 任意の文字列とその変換形を作成
code_verifier = base64.urlsafe_b64encode(os.urandom(30)).decode("utf-8")
code_verifier = re.sub("[^a-zA-Z0-9]+", "", code_verifier)
code_challenge = hashlib.sha256(code_verifier.encode("utf-8")).digest()
code_challenge = base64.urlsafe_b64encode(code_challenge).decode("utf-8")
code_challenge = code_challenge.replace("=", "")

oauth = OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scopes)

#認証URLの生成
auth_url = "https://twitter.com/i/oauth2/authorize"
authorization_url, state = oauth.authorization_url(
    auth_url, code_challenge=code_challenge, code_challenge_method="S256"
)
print(authorization_url)
authorization_response = input(
    "Paste in the full URL after you've authorized your App:\n"
)

token_url = "https://api.twitter.com/2/oauth2/token"
auth = HTTPBasicAuth(client_id, client_secret)

token = oauth.fetch_token(
    token_url=token_url,
    authorization_response=authorization_response,
    auth=auth,
    client_id=client_id,
    include_client_id=True,
    code_verifier=code_verifier,
)
print(token)

# 認証と操作対象設定（事前準備ゴール）
access = token["access_token"]

# リクエスト作成/疎通確認
params = {"user.fields": "created_at,description"}
headers = {
    "Authorization": "Bearer {}".format(access),
    "User-Agent": "auth_test",
}
url = "https://api.twitter.com/2/users/me"
response = requests.request("GET", url, params=params, headers=headers)
if response.status_code != 200:
    raise Exception(
        "Request returned an error: {} {}".format(response.status_code, response.text)
    )
print("finish!")
