# RIS Project

## Run every command in different terminal

- Issues department-based certificates

```br
python3 -m network.authority_server_dept
```

- Issues role-based certificates

```br
python3 -m network.authority_server_role
```

- Verifies certificates, enforces policy, routes encrypted messages

```br
python3 -m cloud.cloud_server_p2p
```

### For Normal Chat

- Generates ECC key pair, encrypts and decrypts ciphertext

```br
python3 -m network.user_client_chat --user userA --channel room1
python3 -m network.user_client_chat --user user2A --channel room1
```

### For Sender Reciever Chat only

- Generates ECC key pair, encrypts message, sends ciphertext

```br
python3 -m network.user_client_sender --user userA --channel room1
```

- Generates ECC key pair, decrypts incoming ciphertext

```br
python3 -m network.user_client_receiver --user user2A --channel room1
```

