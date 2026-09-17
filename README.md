# TipPage oauth example

the smallest client that can connect a streamer's tippage through oauth. no dependencies, just node.

it hosts the callback, does pkce, exchanges the code, stores the tokens in `tokens.json`, refreshes when they expire and can revoke.

## setup

1. in the tippage dashboard go to settings -> developer -> oauth apps -> register app
2. add `http://localhost:3000/callback` as a redirect uri and pick the scopes you want
3. copy the client id, and the client secret if you made a confidential app

```bash
cp .env.example .env
# fill in CLIENT_ID (and CLIENT_SECRET if you have one)
npm start
```

open http://localhost:3000 and click connect. you will be sent to tippage to approve, then back here.

## what each page does

| page | what happens |
|---|---|
| `/connect` | builds the authorize url with a pkce challenge and sends you to tippage |
| `/callback` | tippage lands here with `?code=`, we swap it for tokens |
| `/me` | calls `/v1/me` with the access token, refreshing first if it expired |
| `/queue` | calls `/v1/tts/queue`, needs the `tts:read` scope |
| `/refresh` | forces a refresh, you get a new access and refresh token |
| `/revoke` | tells tippage to drop the authorization and deletes `tokens.json` |

## things to know

- access tokens last an hour, refresh tokens never expire but rotate every time you use one
- keep the newest refresh token, the old one dies as soon as the new one is issued
- if you use an old refresh token the whole connection is revoked and the streamer has to connect again
- a public app (no secret) must send `code_verifier`, this example always does
- the access token works anywhere an api key does, including the realtime socket

full docs: https://docs.tippage.com/api/oauth
