import http.client

conn = http.client.HTTPSConnection("dev-8his2amisscpohz8.us.auth0.com")

payload = "{\"client_id\":\"crdEueHkd1qDu7VaRhM1vdrFrfkNQdSY\",\"client_secret\":\"_jkB6Kup0wD70cRPO3XD0ue9Sulp62qmrbIeYdKKjL1Ia8McxlO42wfh8k0BZI_j\",\"audience\":\"https://jcscoffeeshop510698.com\",\"grant_type\":\"client_credentials\"}"

headers = { 'content-type': "application/json" }

conn.request("POST", "/oauth/token", payload, headers)

res = conn.getresponse()
data = res.read()

print(data.decode("utf-8"))