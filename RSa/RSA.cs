using System;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
namespace RSA
{
    class RSA
    {
        private static BigInteger RandomBigIntInRange(BigInteger min, BigInteger max)
        {

            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();

            // Switch min with max if min is bigger than max
            if (min > max)
            {
                BigInteger temp = min;
                min = max;
                max = temp;
            }

            // offset to set min = 0
            BigInteger offset = -min;
            min = 0;
            max += offset;

            // add the offset back after generating the random number
            BigInteger value = RandomBigIntFromZero(rng, max) - offset;
            return value;
        }

        private static BigInteger RandomBigIntFromZero(RandomNumberGenerator rng, BigInteger max)
        {
            BigInteger value;
            byte[] bytes = max.ToByteArray();

            // count how many bits of the most significant byte are 0
            // NOTE: sign bit is always 0 because `max` must always be positive
            byte ZeroBitsMask = 0b00000000;

            byte MostSignificantByte = bytes[bytes.Length - 1];

            // we try to set to 0 as many bits as there are in the most significant byte, starting from the left (most significant bits first)
            // NOTE: `i` starts from 7 because the sign bit is always 0
            for (int i = 7; i >= 0; i--)
            {
                // we keep iterating until we find the most significant non-0 bit
                if ((MostSignificantByte & (0b1 << i)) != 0)
                {
                    int ZeroBits = 7 - i;
                    ZeroBitsMask = (byte)(0b11111111 >> ZeroBits);
                    break;
                }
            }

            do
            {
                rng.GetBytes(bytes);

                // set most significant bits to 0 (because `value > max` if any of these bits is 1)
                bytes[bytes.Length - 1] &= ZeroBitsMask;

                value = new BigInteger(bytes);

                // `value > max` 50% of the times, in which case the fastest way to keep the distribution uniform is to try again
            } while (value > max);

            return value;
        }

        private static bool MillerRabinTest(BigInteger N, BigInteger D)
        {
            BigInteger a = RandomBigIntInRange(2, N - 2);

            BigInteger x = BigInteger.ModPow(a, D, N);

            if (x == 1 || x == N - 1)
                return true;
            else
                return false;
        }

        private static bool IsPrime(BigInteger N)
        {
            if (N < 2)
                return false;

            if (N == 2 || N == 3)
                return true;

            if (N % 2 == 0)
                return false;

            // Find r such that n = 2^d * r + 1 for some r >= 1 
            BigInteger D = N - 1;
            while (D % 2 == 0)
                D /= 2;

            for (int k = 0; k < 64; k++)
            {
                if (!MillerRabinTest(N, D))
                    return false;
            }

            return true;
        }

        private static BigInteger GetFirstPrime(BigInteger N)
        {
            int Limit = 10000000;
            while (Limit-- > 0)
            {
                if (IsPrime(N))
                {
                    return N;
                }

                N++;
            }

            Console.WriteLine("GetFirstPrime reached test limit: 10000000");
            return 2;

        }

        private static BigInteger GetLargeRandomPrime()
        {
            // Generate an array of bits of which all bits are 1 (aka. largest value)
            byte[] max = Enumerable.Repeat((byte)0xFF, 32).ToArray();

            max[max.Length - 1] &= 0x7F;
            // turn the byte array into a big int
            BigInteger Bmax = new BigInteger(max);

            // generate a random number between 
            BigInteger N = RandomBigIntInRange(Bmax / 8, Bmax);

            if (IsPrime(N))
                return N;

            else
                return GetFirstPrime(N);
        }

        private static BigInteger GCD(BigInteger a, BigInteger b)
        {
            while (a != 0 && b != 0)
            {
                if (a > b)
                    a %= b;
                else
                    b %= a;
            }

            return a == 0 ? b : a;
        }

        private static BigInteger ModInverse(BigInteger a, BigInteger n)
        {
            BigInteger i = n, v = 0, d = 1;
            while (a > 0)
            {
                BigInteger t = i / a, x = a;
                a = i % x;
                i = x;
                x = d;
                d = v - t * x;
                v = x;
            }
            v %= n;
            if (v < 0) v = (v + n) % n;
            return v;
        }

        public static void GenerateKeyPair(out RSAKey PublicKey, out RSAKey PrivateKey)
        {
            // Generate a large prime number for P
            BigInteger P = GetLargeRandomPrime();

            // generate a large prime number for Q
            BigInteger Q = GetLargeRandomPrime();

            BigInteger N = P * Q;

            BigInteger Phi = (P - 1) * (Q - 1);

            BigInteger e;

            e = 65537;

            while (GCD(e, Phi) != 1)
            {
                e = GetFirstPrime(e);
            }

            BigInteger d = ModInverse(e, Phi);

            PublicKey.N = N;
            PublicKey.Key = e;

            PrivateKey.N = N;
            PrivateKey.Key = d;

            Console.WriteLine("Public Key is: \n" + PublicKey.ToString("X"));
            Console.WriteLine("Private Key is: \n" + PrivateKey.ToString("X"));
        }

        public static BigInteger Encrypt(BigInteger M, RSAKey EncryptionKey)
        {

            return BigInteger.ModPow(M, EncryptionKey.Key, EncryptionKey.N);
        }

    }

    struct RSAKey
    {
        public BigInteger Key;
        public BigInteger N;

        public RSAKey(BigInteger Key, BigInteger N)
        {
            this.Key = Key;
            this.N = N;
        }

        public override string ToString()
        {
            return "Key: " + Key.ToString() + ", N: " + N.ToString();
        }

        public string ToString(string format)
        {
            return "Key: " + Key.ToString(format) + ", N: " + N.ToString(format);
        }
    }
}
