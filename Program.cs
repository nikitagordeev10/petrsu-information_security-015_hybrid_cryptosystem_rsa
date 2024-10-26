using KSZI;
using System;
using System.IO;
using System.Security.Cryptography;

namespace KSZI
{
    class Program
    {
        static void Main()
        {
            try
            {
                // Инициализация объектов для шифрования и дешифрования
                EncryptFile encryptFile = new EncryptFile();
                DecryptFile decryptFile = new DecryptFile();

                // Шифрование файла
                Console.WriteLine("Пользователь 1 - отправляет файл");
                encryptFile.Encrypt();

                // Дешифрование файла
                Console.WriteLine("Пользователь - 2 получает файл");
                decryptFile.Decrypt();
            } catch (Exception ex)
            {
                // Обработка исключений
                Console.WriteLine("Произошла ошибка: " + ex.Message);
            }
        }
    }
}