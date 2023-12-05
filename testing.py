import requests
import json

msg = input("Message to send to pastebin site: ")

postId = requests.post('http://cs448lnx101.gcc.edu/posts/create', data={'contents': msg})

print(f"Post ID: {postId.json()['id']}")

# response = requests.get(f"http://cs448lnx101.gcc.edu/posts/view/{postId}")

# print(response)