import argparse

def xor_decrypt(data: bytes, key: bytes) -> bytes:
    key_len = len(key)
    return bytes([b ^ key[i % key_len] for i, b in enumerate(data)])

def main():
    parser = argparse.ArgumentParser(description="Decrypt XOR-obfuscated dump")
    parser.add_argument("-d", "--dump", required=True, help="Path to XORed dump file")
    parser.add_argument("-x", "--xorkey", required=True, help="XOR key string")
    parser.add_argument("-o", "--output", required=True, help="Output file path")

    args = parser.parse_args()

    try:
        with open(args.dump, "rb") as f:
            encrypted_data = f.read()
    except IOError as e:
        print(f"[-] Failed to read dump file: {e}")
        return

    xor_key = args.xorkey.encode("utf-8")
    decrypted_data = xor_decrypt(encrypted_data, xor_key)

    try:
        with open(args.output, "wb") as f:
            f.write(decrypted_data)
        print(f"[+] Decrypted dump written to: {args.output}")
    except IOError as e:
        print(f"[-] Failed to write output file: {e}")

if __name__ == "__main__":
    main()