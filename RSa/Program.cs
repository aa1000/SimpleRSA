using RSA;
using System;
using System.Globalization;
using System.Numerics;

namespace RSA
{
    class Program
    {
        static void Main(string[] args)
        {
            // First create 2 vars of type RSAKey, one for public key and one for private key
            RSAKey PU, PV;

            // Generate the key pair
            RSA.GenerateKeyPair(out PU, out PV);

            // 64 bit key in hex format as a string
            string key = "4D6251655468576D";

            // p = plain text key in numeric form (must use BigInteger for large numbers)
            // converting a hex string into numeric from but the key has to have a '0' in the MSB (start)
            BigInteger p = BigInteger.Parse("0" + key, NumberStyles.AllowHexSpecifier);

            // Encrypting the plain text with private key (encrypt function can take any key but the message M has to be a BigInteger)
            BigInteger c = RSA.Encrypt(p, PV);

            // Encrypt again with public key to decrypt the message
            BigInteger m = RSA.Encrypt(c, PU);

            Console.WriteLine("input: " + key);
            Console.WriteLine("cypher: " + c.ToString("X"));
            Console.WriteLine("output: " + m.ToString("X"));

            Console.Read();
        }
    }


}
