using System.Security.Cryptography;
using System.Text;
using System.Buffers;

namespace Task1;

internal class Program
{
    static void Main(string[] args)
    {
        var salt = "saltsaltsaltsalt";
        var hash1 = GeneratePasswordHashUsingSalt("Hello, World!", Encoding.UTF8.GetBytes(salt));
        var hash2 = BetterGeneratePasswordHashUsingSalt("Hello, World!", Encoding.UTF8.GetBytes(salt));
        Console.WriteLine($"are hash1 and hash2 equal?: {hash1 == hash2}");
    }

    public static string GeneratePasswordHashUsingSalt(string passwordText, byte[] salt)
    {
        var iterate = 10000;
        var pbkdf2 = new Rfc2898DeriveBytes(passwordText, salt, iterate);

        byte[] hash = pbkdf2.GetBytes(20);
        byte[] hashBytes = new byte[36];

        Array.Copy(salt, 0, hashBytes, 0, 16);
        Array.Copy(hash, 0, hashBytes, 16, 20);

        var passwordHash = Convert.ToBase64String(hashBytes);
        return passwordHash;
    }

    public static string BetterGeneratePasswordHashUsingSalt(string passwordText, byte[] salt)
    {
        const int RequiredSaltLength = 16;

        if (salt is null)
        {
            throw new ArgumentNullException(nameof(salt), "Salt may not be null.");
        }

        if (salt.Length < RequiredSaltLength)
        {
            throw new ArgumentException(
                $"Salt must be at least {RequiredSaltLength} bytes long, but was {salt.Length}.",
                nameof(salt)
            );
        }

        const int iterations = 10000;
        int saltLength = salt.Length;
        int hashLength = 20;

        byte[] buffer = ArrayPool<byte>.Shared.Rent(saltLength + hashLength);
        try
        {
            Buffer.BlockCopy(salt, 0, buffer, 0, saltLength);

            using (Rfc2898DeriveBytes pbkdf2 = new(passwordText, salt, iterations))
            {
                byte[] hash = pbkdf2.GetBytes(hashLength);
                Buffer.BlockCopy(hash, 0, buffer, saltLength, hashLength);
            }

            return Convert.ToBase64String(buffer, 0, saltLength + hashLength);
        }
        finally
        {
            Array.Clear(buffer, 0, saltLength + hashLength);
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }
}
