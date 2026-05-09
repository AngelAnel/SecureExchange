# Secure Information Exchange Program

A console-based simulation of a secure messaging system between two users (User A and User B) using **Diffie-Hellman Key Exchange** and **AES-128 Encryption**.

---

## What It Does

This program simulates a secure communication channel where:

1. **User A and User B exchange encryption keys** without directly sending the key to each other, using the Diffie-Hellman algorithm.
2. **A shared secret key is derived** from both users' private keys and transformed into a 128-bit AES key.
3. **User A encrypts a message** by splitting it into 16-character blocks and encrypting each block using the AES key.
4. **User B decrypts the message** by receiving the encrypted blocks and reversing the encryption using the same shared key.

The program walks through each step in a clean, readable console output — making it easy to follow the entire process from key exchange to decryption.

---

## How It Works

### Step 1 — Diffie-Hellman Key Exchange
- Fixed parameters: Prime `p = 199`, Generator `g = 127`
- Each user has a private key
- Public values are computed as `g^privateKey mod p`
- The shared key is computed as `otherPublicValue^myPrivateKey mod p`
- Both users arrive at the same shared key without ever sending it directly

### Step 2 — Building the 128-bit AES Key
The shared key is stretched into a 16-character key using these rules:
- **1 digit** → alternate with `C` (e.g. `1C1C1C1C1C1C1C1C`)
- **2 digits** → alternate with `DD` (e.g. `58DD58DD58DD58DD`)
- **3 digits** → use `F` as separator (e.g. `109F109F109F109F`)

### Step 3 — Encryption
- The message is split into 16-character blocks
- If the last block is shorter than 16 characters, it is padded with `@`
- Each block is XOR-encrypted using the AES key
- All encrypted blocks are concatenated and transmitted

### Step 4 — Decryption
- The received encrypted message is split back into 16-character blocks
- Each block is XOR-decrypted using the same AES key
- The blocks are reassembled and padding is removed to recover the original message

---

## Language Used

- **Java** — compiled and run via the JDK
- No external libraries required, uses only the Java standard library

---

## How to Run

1. Make sure you have the [Java JDK](https://www.oracle.com/java/technologies/downloads/) installed
2. Compile the program:
   ```bash
   javac Secureexchange.java
   ```
3. Run the program:
   ```bash
   java Secureexchange
   ```
4. Enter the private keys for User A and User B, and the message to encrypt

---

## Sample Run

```
  Enter Private Key for User A : 57
  Enter Private Key for User B : 167
  Enter Message                : The Mandalorian Must Always Recite, This is The Way!
```

Expected shared key: `109`  
Expected AES-128 key: `109F109F109F109F`  
Expected decrypted output: `The Mandalorian Must Always Recite, This is The Way!`
