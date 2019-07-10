using System;
using System.IO;
using System.Security.Cryptography;

namespace Encrytor
{
    public class AesEncrytor
    {
        public static void Main()
        {
            byte[] key = { 0x3a, 0xb0, 0x5c, 0xe0, 0x10, 0x9b, 0x33, 0x8b, 0xcc, 0xe9, 0xd1, 0x0a, 0x00, 0xa7, 0xdd, 0x4d };
            byte[] IV = { 0x1e, 0x0b, 0xd3, 0x0e, 0x06, 0x99, 0x3c, 0xb5, 0xc5, 0xe1, 0x1a, 0xee, 0x15, 0x47, 0x6a, 0xb2 };

            while (true)
            {
                System.Console.Write("문자열 입력 : ");
                string input = System.Console.ReadLine();
                string output = null;
                System.Console.Write("(E)ncrypt / (D)ecrypt / (Q)uit : ");
                var keyInfo = System.Console.ReadKey();
                System.Console.WriteLine();
                if (keyInfo.Key == ConsoleKey.E)
				{
                    output = System.Convert.ToBase64String(EncryptStringToBytes_Aes(input, key, IV));
				}
                else if (keyInfo.Key == ConsoleKey.D)
                {
                    input = input.Replace("!", "");
                    input = input.Replace(" ", "");
                    output = DecryptStringFromBytes_Aes(System.Convert.FromBase64String(input), key, IV);
                }
                else if (keyInfo.Key == ConsoleKey.Q)
				{
                    break;
				}
                else
				{
                    break;
				}

                System.Console.WriteLine(output);
                System.Console.WriteLine();

            }
            System.Console.WriteLine("종료합니다.");
        }
        static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
			{
                throw new ArgumentNullException("plainText");
			}
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }


            // Return the encrypted bytes from the memory stream.
            return encrypted;

        }

        static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
			{
                throw new ArgumentNullException("cipherText");
			}
            if (Key == null || Key.Length <= 0)
			{
                throw new ArgumentNullException("Key");
			}
            if (IV == null || IV.Length <= 0)
			{
                throw new ArgumentNullException("IV");
			}

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }

            }

            return plaintext;

        }
    }
}
