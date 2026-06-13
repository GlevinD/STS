from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import requests

private_key_pem = b"""-----BEGIN RSA PRIVATE KEY-----
MIIEoQIBAAKCAQEAuNnyYeFvsdWz88oee5N5NWyPBOnppz9w7VZhVmyIOXYOZ46JEVI0nQMk51SzqALfJidPHRbwu8LanZv9OSp9DvhqP/UbWum49NwDzkLNc2YLYWL3FOZfoFwZ6H4mmTvJ69+CjiqqibUWgqRP2ODmZh2IgrGJbDgb0r4QnXv516ryVFk+/xgbvSRAKz8+2moZK021D8dQibIaz3fx4/zQ0tlGM/sTmRHcf+gvqOmDPqCe2y4o58MTk8s3SYLYkno9EJ5SVeJN3eCFukPl62qzyhmdIYcI0ZlrMXjkGqjA0v3joG3WFJwPijOkUn1vyt9FB/DC3ubDectaQ+tR0WDj0QIDAQABAoH/a8Skyuvjcopkn3z2yJTx1XO07ehxkFAsRjJWDUy5Hsb1Huq6fp6ujduHaFa5ZvpFnrjMJul47/5p9fk7aFidEF1DlIYRrK8WZarfjSDlJqIXgG9yHX0xwwvvDtx9JFj3H8zvEHNPeXlZ5lBlPMvhhycwrwFSXQVZM0Qb67SbtF+3CdczMhtMDP1DosPiYHUXyPfKp7k32kuOdxpiWQNxraLfbwKIBy2i9NV71aXxUCDAawz0+cSEyeKc1Qk0VuLsif7fMVKAtZYtg1HkeL+5LXEUJCarC1Zi0HySVM0GIHpRWd1FuTFQNNkrZA/zCDOnpDGB1SG30RuxJBR+YsRRAoGBAMnH8u1+yUXfx3Fv+r/BUE1Wx0VIo75i+zPIQWEutKYdDC36DQffEJk41G/AsXZG5YbBuGCuX/VfHJEFw1IBArP84WEgfY6M7jBmyHm5D5lvmv67n1WcWthfNtBJYvY9VcDz6+PxuJMMXZC6HEoFXi74tq4jiMOcR9yxSaJ/i/BJAoGBAOqFcXy/rMHeligjaw4TzDvDRLJ2EVlq313KeiWXAw6CNMd9dFLYF0dVtRXPHyILw4860VVCAcmiMZsr6KDwgc3QjX9ANav3K/zR/DpiI+Fyp1hcE8QGfpX9yVkrHN+4YzEeQkUsz7Kx37kifN2RyanW4llMESfVPEr5giaWbGdJAoGAOVwTnJu8D5brlT2l5DjJ4RJYF0Ps+EQe8LtuinfCdq4vNiqs5Z3tlADpstLuH5dLzCDpjuJC+PeOoVMoEPmkkRHD595aktlRJIUzXBbVbmKhhuRDCQ0nbfazGEakUSdiZzVvyx59v592QZwGSqx395ZQJ/SF/kVA0GW9buofF7ECgYA8fX7wNmBRASCp6bjLQMAFCjDF9z4yWiaTAo7O80yOiXcjnXBLjgEzHSBAJ9RX68DdSMaFvyjG4Vb6NzEhkedpNsnIcL9nQ7HM3Dy6smWe2PvhBp7yiNpNxdARd9VSvzSWjr95KD3KUabrEcIzRE9Hx21KqxwhshaDICg528LKQQKBgQCXa8vtDVNjz4gWyO5GxVTCNOlNe2oB//ZdxQtYeaCszQgVfzo9vZvvCv8bZWL26x+gn6+/opf276wzD7USxzQSFGyAyOXFmTM0sfjL8gdkbpDFvC/6oC7A1GW3/ICbzGnhvJFOlkRXO+B/QaXeQy32AMBIMQAqYQLWWrVD7UYsSw==
-----END RSA PRIVATE KEY-----"""

private_key = RSA.import_key(private_key_pem)

# Step 2: Request challenge from server
resp = requests.post(
    "http://127.0.0.1:5000/entry-challenge",
    json={"ticket_hash": "687d87806dc4effdafbf1b7d709e5afd1dfc6c99dd03cac17c46deec936fb556"}
)
challenge = resp.json()["challenge"]

# Step 3: Sign challenge
h = SHA256.new(challenge.encode())
signature = pkcs1_15.new(private_key).sign(h)

# Step 4: Send signature back to server
verify = requests.post(
    "http://127.0.0.1:5000/verify-entry",
    json={
        "ticket_hash": "687d87806dc4effdafbf1b7d709e5afd1dfc6c99dd03cac17c46deec936fb556",
        "signature": signature.hex()
    }
)

print(verify.json())