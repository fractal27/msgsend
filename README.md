# Message send

This is a simple implementation of a simple E2EE communication based server, which uses `libgpg` to encrypt/decrypt messages
in the client; and the server simply relays the encrypted messages and the other public keys to the client, which imports
the keys, and decrypts/encrypts the messages to each individual recepient.

![Demo video](demo/demo.gif)



## Features coming up

- Groups
- Single user whispers
- Notifications
- User-friendly commands
- Crossplatform support? (will see but I doubt it)

Also see [TODO](./TODO)
