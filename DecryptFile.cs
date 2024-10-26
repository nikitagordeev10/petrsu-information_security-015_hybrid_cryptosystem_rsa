using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace KSZI
{
    public class DecryptFile
    {
        private const string FilePath = "encryptedData.txt";
        private const string PrivateKeyFilePath = "privateKey.pem";
        private const string PublicKeyFilePath = "publicKey.pem";
        private const string DecryptedFilePath = "decryptedData.txt";

        public void Decrypt()
        {
            Console.WriteLine("Начинается расшифровка");
            try
            {
                // Чтение зашифрованных данных из файла
                var (encryptedKey, encryptedIV, encryptedData, signature) = ReadEncryptedFile(FilePath);

                // Проверка цифровой подписи
                if (!VerifySignature(encryptedData, signature, PublicKeyFilePath))
                {
                    Console.WriteLine("Подпись не совпадает!");
                    return;
                }

                // Расшифровка симметричного ключа и IV с помощью закрытого ключа RSA
                byte[] key = DecryptData(encryptedKey, PrivateKeyFilePath);
                byte[] iv = DecryptData(encryptedIV, PrivateKeyFilePath);

                // Расшифровка данных симметричным алгоритмом AES
                string decryptedText = DecryptAesData(encryptedData, key, iv);

                // Сохранение расшифрованного сообщения в файл
                SaveDecryptedFile(decryptedText, DecryptedFilePath);

                // Вывод расшифрованного сообщения
                Console.WriteLine("Расшифрованное сообщение сохранено в: " + DecryptedFilePath);
            } catch (Exception ex)
            {
                // Обработка ошибок
                Console.WriteLine($"Ошибка при расшифровке: {ex.Message}");
            }
        }

        /// <summary>
        /// Читает зашифрованный файл и извлекает из него данные.
        /// </summary>
        private (byte[] encryptedKey, byte[] encryptedIV, byte[] encryptedData, byte[] signature) ReadEncryptedFile(string filePath)
        {
            try
            {
                using (BinaryReader reader = new BinaryReader(File.Open(filePath, FileMode.Open)))
                {
                    // Чтение зашифрованного ключа
                    byte[] encryptedKey = reader.ReadBytes(reader.ReadInt32());
                    // Чтение зашифрованного IV
                    byte[] encryptedIV = reader.ReadBytes(reader.ReadInt32());
                    // Чтение зашифрованных данных
                    byte[] encryptedData = reader.ReadBytes(reader.ReadInt32());
                    // Чтение цифровой подписи
                    byte[] signature = reader.ReadBytes(reader.ReadInt32());

                    return (encryptedKey, encryptedIV, encryptedData, signature);
                }
            } catch (IOException ex)
            {
                // Обработка ошибок при чтении файла
                throw new Exception("Ошибка при чтении зашифрованного файла", ex);
            }
        }

        /// <summary>
        /// Проверяет цифровую подпись данных.
        /// </summary>
        private bool VerifySignature(byte[] data, byte[] signature, string publicKeyFilePath)
        {
            try
            {
                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                {
                    // Чтение открытого ключа из файла
                    string publicKey = File.ReadAllText(publicKeyFilePath);
                    rsa.FromXmlString(publicKey);

                    // Проверка цифровой подписи
                    return rsa.VerifyData(data, SHA256.Create(), signature);
                }
            } catch (CryptographicException ex)
            {
                // Обработка ошибок при проверке подписи
                throw new Exception("Ошибка при проверке цифровой подписи", ex);
            }
        }

        /// <summary>
        /// Расшифровывает данные с использованием закрытого ключа RSA.
        /// </summary>
        private byte[] DecryptData(byte[] data, string privateKeyFilePath)
        {
            try
            {
                // Чтение закрытого ключа из файла
                string privateKey = File.ReadAllText(privateKeyFilePath);
                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                {
                    rsa.FromXmlString(privateKey);

                    // Расшифровка данных с использованием RSA
                    return rsa.Decrypt(data, RSAEncryptionPadding.Pkcs1);
                }
            } catch (CryptographicException ex)
            {
                // Обработка ошибок при расшифровке данных
                throw new Exception("Ошибка при расшифровке данных с использованием закрытого ключа", ex);
            }
        }

        /// <summary>
        /// Расшифровывает зашифрованные данные с использованием алгоритма AES.
        /// </summary>
        private string DecryptAesData(byte[] encryptedData, byte[] key, byte[] iv)
        {
            try
            {
                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;

                    using (MemoryStream ms = new MemoryStream(encryptedData))
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read))
                    using (StreamReader sr = new StreamReader(cs))
                    {
                        // Чтение и расшифровка данных
                        return sr.ReadToEnd();
                    }
                }
            } catch (CryptographicException ex)
            {
                // Обработка ошибок при расшифровке данных AES
                throw new Exception("Ошибка при расшифровке данных с использованием AES", ex);
            }
        }

        /// <summary>
        /// Сохраняет расшифрованное сообщение в файл.
        /// </summary>
        private void SaveDecryptedFile(string decryptedText, string filePath)
        {
            try
            {
                File.WriteAllText(filePath, decryptedText, Encoding.UTF8);
            } catch (IOException ex)
            {
                // Обработка ошибок при сохранении файла
                throw new Exception("Ошибка при сохранении расшифрованного файла", ex);
            }
        }
    }
}
