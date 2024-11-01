from sha.sha1_hash import sha1


text = "jrahyn+"
hash_value = sha1(text.encode())
print("SHA-1 Hash:", hash_value)
