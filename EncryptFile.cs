using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace KSZI
{
    public class EncryptFile
    {
        private const string TextFilePath = "secretMessage.txt"; // Путь к текстовому файлу с исходным сообщением
        private const string EncryptedFilePath = "encryptedData.txt"; // Путь к файлу, в который будут сохранены зашифрованные данные
        private const string PrivateKeyFilePath = "privateKey.pem"; // Путь к файлу с закрытым ключом
        private const string PublicKeyFilePath = "publicKey.pem"; // Путь к файлу с открытым ключом

        public void Encrypt()
        {
            Console.WriteLine($"Начинается шифрование");
            try
            {
                // Генерация и сохранение пары ключей RSA
                GenerateAndSaveRSAKeys();

                // Чтение текста из файла
                string text = File.ReadAllText(TextFilePath);

                // Генерация симметричного ключа и IV для AES и шифрование данных
                var (key, iv, encryptedData) = EncryptWithAES(text);

                // Шифрование симметричного ключа и IV с использованием открытого ключа RSA
                byte[] encryptedKey = EncryptDataWithRSA(key, PublicKeyFilePath);
                byte[] encryptedIV = EncryptDataWithRSA(iv, PublicKeyFilePath);

                // Генерация электронной подписи данных с использованием закрытого ключа RSA
                byte[] signature = GenerateSignature(encryptedData);

                // Запись зашифрованных данных и ключей в файл
                WriteEncryptedDataToFile(encryptedKey, encryptedIV, encryptedData, signature);
                Console.WriteLine($"Файл зашифрован, данные сохранены в файле {EncryptedFilePath}");
            }
            catch (Exception ex)
            {
                // Обработка ошибок и вывод сообщения об ошибке
                Console.WriteLine($"Ошибка при шифровании: {ex.Message}");
            }
        }

        /// <summary>
        /// Генерирует и сохраняет пару ключей RSA в файлы.
        /// </summary>
        private void GenerateAndSaveRSAKeys()
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                // Сохранение закрытого ключа
                string privateKey = rsa.ToXmlString(true);
                File.WriteAllText(PrivateKeyFilePath, privateKey);

                // Сохранение открытого ключа
                string publicKey = rsa.ToXmlString(false);
                File.WriteAllText(PublicKeyFilePath, publicKey);
            }
        }

        /// <summary>
        /// Шифрует текст с использованием AES 
        /// Возвращает ключ, IV и зашифрованные данные.
        ///     IV (Initialization Vector, вектор инициализации) — это дополнительный ввод, используемый с секретным ключом для повышения безопасности шифрования. 
        ///     В алгоритме AES IV гарантирует, что одинаковые данные, зашифрованные с одним и тем же ключом, будут иметь разные зашифрованные выходные данные.
        /// </summary>
        private (byte[] key, byte[] iv, byte[] encryptedData) EncryptWithAES(string text)
        {
            using (Aes aes = Aes.Create())
            {
                byte[] key = aes.Key; // Генерация симметричного ключа
                byte[] iv = aes.IV; // Генерация вектора инициализации (IV)
                byte[] encryptedData;

                using (MemoryStream ms = new MemoryStream())
                using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                using (StreamWriter sw = new StreamWriter(cs))
                {
                    // Запись текста в поток, зашифрованный с помощью AES
                    sw.Write(text);
                    sw.Flush();
                    cs.FlushFinalBlock();
                    encryptedData = ms.ToArray(); // Получение зашифрованных данных из памяти
                }

                return (key, iv, encryptedData);
            }
        }

        /// <summary>
        /// Шифрует данные с использованием открытого ключа RSA.
        /// </summary>
        private byte[] EncryptDataWithRSA(byte[] data, string publicKeyFilePath)
        {
            string publicKey = File.ReadAllText(publicKeyFilePath);
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(publicKey); // Импорт открытого ключа из строки XML
                return rsa.Encrypt(data, RSAEncryptionPadding.Pkcs1); // Шифрование данных с использованием RSA
            }
        }

        /// <summary>
        /// Генерирует цифровую подпись данных с использованием закрытого ключа RSA.
        /// </summary>
        private byte[] GenerateSignature(byte[] data)
        {
            string privateKey = File.ReadAllText(PrivateKeyFilePath);
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(privateKey); // Импорт закрытого ключа из строки XML
                return rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1); // Создание подписи данных
            }
        }

        /// <summary>
        /// Записывает зашифрованные данные, ключи и подпись в файл.
        /// </summary>
        private void WriteEncryptedDataToFile(byte[] encryptedKey, byte[] encryptedIV, byte[] encryptedData, byte[] signature)
        {
            using (BinaryWriter writer = new BinaryWriter(File.Open(EncryptedFilePath, FileMode.Create)))
            {
                // Запись зашифрованного ключа
                writer.Write(encryptedKey.Length);
                writer.Write(encryptedKey);

                // Запись зашифрованного IV
                writer.Write(encryptedIV.Length);
                writer.Write(encryptedIV);

                // Запись зашифрованных данных
                writer.Write(encryptedData.Length);
                writer.Write(encryptedData);

                // Запись электронной подписи
                writer.Write(signature.Length);
                writer.Write(signature);
            }
        }
    }
}
