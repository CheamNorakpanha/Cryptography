from cryptography.fernet import Fernet

class CryptographyTool:
    def __init__(self):
        self.key_file = "secret.key"

    def generate_key(self):
        """Generate a new encryption key and save it to a file."""
        key = Fernet.generate_key()
        with open(self.key_file, "wb") as key_file:
            key_file.write(key)
        print("\nA new key has been generated.")

    def load_key(self):
        """Load the encryption key from the key file."""
        return open(self.key_file, "rb").read()

    def encrypt_message(self, message):
        """Encrypt a message using the loaded key."""
        key = self.load_key()
        fernet = Fernet(key)
        encrypted_message = fernet.encrypt(message.encode())
        return encrypted_message

    def decrypt_message(self, encrypted_message):
        """Decrypt a previously encrypted message using the loaded key."""
        key = self.load_key()
        fernet = Fernet(key)
        try:
            decrypted_message = fernet.decrypt(encrypted_message).decode()
            return decrypted_message
        except Exception as e:
            print("\nDecryption failed:", e)
            return None

    def run(self):
        """Run the tool, allowing the user to choose encryption, decryption, or exit."""
        while True:
            print("\n======================================================================")
            print("========================> Choose an option: <=========================")
            print("======================================================================\n")
            print("\tA: Encrypt a message")
            print("\tB: Decrypt a message")
            print("\tC: Exit\n")
            print("======================================================================")
            choice = input("\n=> Enter your choice (A/B/C): ").strip().upper()

            if choice == "A":
                original_message = input("\n=> Enter the message to encrypt: ")
                self.generate_key()
                encrypted = self.encrypt_message(original_message)
                print("\n===================================================================================================================================================")
                print("\t=> Encrypted message (base64):", encrypted.decode())  # Print as string
                print("===================================================================================================================================================")

            elif choice == "B":
                encrypted_input = input("\n=> Enter the encrypted message (base64 format): ")
                try:
                    encrypted_bytes = encrypted_input.encode()  # Encode the input as bytes
                    decrypted = self.decrypt_message(encrypted_bytes)
                    if decrypted is not None:
                        print("\n======================================================================")
                        print("\t=> Decrypted message:", decrypted)
                        print("======================================================================")
                except Exception as e:
                    print("\n======================================================================")
                    print("\tAn error occurred:", e)
                    print("======================================================================")

            elif choice == "C":
                print("\n======================================================================")
                print("====================> Exiting the tool. Goodbye! <====================")
                print("======================================================================")
                break

            else:
                print("\n======================================================================")
                print("=========> Invalid choice. Please choose either A, B, or C. <=========")
                print("======================================================================")

if __name__ == "__main__":
    tool = CryptographyTool()
    tool.run()