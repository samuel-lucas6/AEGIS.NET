using AegisDotNet;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace AegisDotNetTests;

[TestClass]
public class AEGIS128LTests
{
    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-aegis-aead#appendix-A.2
    public static IEnumerable<object[]> ValidTestVectors()
    {
        // Test Vector 1
        yield return
        [
            "c1c0e58bd913006feba00f4b3cc3594eabe0ece80c24868a226a35d16bdae37a",
            "00000000000000000000000000000000",
            "10000200000000000000000000000000",
            "10010000000000000000000000000000",
            "",
            AEGIS128L.MinTagSize
        ];
        yield return
        [
            "c1c0e58bd913006feba00f4b3cc3594e25835bfbb21632176cf03840687cb968cace4617af1bd0f7d064c639a5c79ee4",
            "00000000000000000000000000000000",
            "10000200000000000000000000000000",
            "10010000000000000000000000000000",
            "",
            AEGIS128L.MaxTagSize
        ];
        // Test Vector 2
        yield return
        [
            "c2b879a67def9d74e6c14f708bbcc9b4",
            "",
            "10000200000000000000000000000000",
            "10010000000000000000000000000000",
            "",
            AEGIS128L.MinTagSize
        ];
        yield return
        [
            "1360dc9db8ae42455f6e5b6a9d488ea4f2184c4e12120249335c4ee84bafe25d",
            "",
            "10000200000000000000000000000000",
            "10010000000000000000000000000000",
            "",
            AEGIS128L.MaxTagSize
        ];
        // Test Vector 3
        yield return
        [
            "79d94593d8c2119d7e8fd9b8fc77845c5c077a05b2528b6ac54b563aed8efe84cc6f3372f6aa1bb82388d695c3962d9a",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "10000200000000000000000000000000",
            "10010000000000000000000000000000",
            "0001020304050607",
            AEGIS128L.MinTagSize
        ];
        yield return
        [
            "79d94593d8c2119d7e8fd9b8fc77845c5c077a05b2528b6ac54b563aed8efe84022cb796fe7e0ae1197525ff67e309484cfbab6528ddef89f17d74ef8ecd82b3",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "10000200000000000000000000000000",
            "10010000000000000000000000000000",
            "0001020304050607",
            AEGIS128L.MaxTagSize
        ];
        // Test Vector 4
        yield return
        [
            "79d94593d8c2119d7e8fd9b8fc775c04b3dba849b2701effbe32c7f0fab7",
            "000102030405060708090a0b0c0d",
            "10000200000000000000000000000000",
            "10010000000000000000000000000000",
            "0001020304050607",
            AEGIS128L.MinTagSize
        ];
        yield return
        [
            "79d94593d8c2119d7e8fd9b8fc7786f1b80bfb463aba711d15405d094baf4a55a15dbfec81a76f35ed0b9c8b04ac",
            "000102030405060708090a0b0c0d",
            "10000200000000000000000000000000",
            "10010000000000000000000000000000",
            "0001020304050607",
            AEGIS128L.MaxTagSize
        ];
        // Test Vector 5
        yield return
        [
            "b31052ad1cca4e291abcf2df3502e6bdb1bfd6db36798be3607b1f94d34478aa7ede7f7a990fec107542a745733014f9474417b337399507",
            "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637",
            "10000200000000000000000000000000",
            "10010000000000000000000000000000",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829",
            AEGIS128L.MinTagSize
        ];
        yield return
        [
            "b31052ad1cca4e291abcf2df3502e6bdb1bfd6db36798be3607b1f94d34478aa7ede7f7a990fec10b91e2947a33da8bee89b6794e647baf0fc835ff574aca3fc27c33be0db2aff98",
            "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637",
            "10000200000000000000000000000000",
            "10010000000000000000000000000000",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829",
            AEGIS128L.MaxTagSize
        ];
    }

    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-aegis-aead#appendix-A.2.7
    public static IEnumerable<object[]> TamperedTestVectors()
    {
        // Test Vector 6
        yield return
        [
            "79d94593d8c2119d7e8fd9b8fc775c04b3dba849b2701effbe32c7f0fab7",
            "10010000000000000000000000000000",
            "10000200000000000000000000000000",
            "0001020304050607",
            AEGIS128L.MinTagSize
        ];
        yield return
        [
            "79d94593d8c2119d7e8fd9b8fc7786f1b80bfb463aba711d15405d094baf4a55a15dbfec81a76f35ed0b9c8b04ac",
            "10010000000000000000000000000000",
            "10000200000000000000000000000000",
            "0001020304050607",
            AEGIS128L.MaxTagSize
        ];
        // Test Vector 7
        yield return
        [
            "79d94593d8c2119d7e8fd9b8fc785c04b3dba849b2701effbe32c7f0fab7",
            "10000200000000000000000000000000",
            "10010000000000000000000000000000",
            "0001020304050607",
            AEGIS128L.MinTagSize
        ];
        yield return
        [
            "79d94593d8c2119d7e8fd9b8fc7886f1b80bfb463aba711d15405d094baf4a55a15dbfec81a76f35ed0b9c8b04ac",
            "10000200000000000000000000000000",
            "10010000000000000000000000000000",
            "0001020304050607",
            AEGIS128L.MaxTagSize
        ];
        // Test Vector 8
        yield return
        [
            "79d94593d8c2119d7e8fd9b8fc775c04b3dba849b2701effbe32c7f0fab7",
            "10000200000000000000000000000000",
            "10010000000000000000000000000000",
            "0001020304050608",
            AEGIS128L.MinTagSize
        ];
        yield return
        [
            "79d94593d8c2119d7e8fd9b8fc7786f1b80bfb463aba711d15405d094baf4a55a15dbfec81a76f35ed0b9c8b04ac",
            "10000200000000000000000000000000",
            "10010000000000000000000000000000",
            "0001020304050608",
            AEGIS128L.MaxTagSize
        ];
        // Test Vector 9
        yield return
        [
            "79d94593d8c2119d7e8fd9b8fc776c04b3dba849b2701effbe32c7f0fab8",
            "10000200000000000000000000000000",
            "10010000000000000000000000000000",
            "0001020304050607",
            AEGIS128L.MinTagSize
        ];
        yield return
        [
            "79d94593d8c2119d7e8fd9b8fc7786f1b80bfb463aba711d15405d094baf4a55a15dbfec81a76f35ed0b9c8b04ad",
            "10000200000000000000000000000000",
            "10010000000000000000000000000000",
            "0001020304050607",
            AEGIS128L.MaxTagSize
        ];
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return [AEGIS128L.MinTagSize, 1, AEGIS128L.NonceSize, AEGIS128L.KeySize, 16, AEGIS128L.MinTagSize];
        yield return [AEGIS128L.MinTagSize, 0, AEGIS128L.NonceSize + 1, AEGIS128L.KeySize, 16, AEGIS128L.MinTagSize];
        yield return [AEGIS128L.MinTagSize, 0, AEGIS128L.NonceSize - 1, AEGIS128L.KeySize, 16, AEGIS128L.MinTagSize];
        yield return [AEGIS128L.MinTagSize, 0, AEGIS128L.NonceSize, AEGIS128L.KeySize + 1, 16, AEGIS128L.MinTagSize];
        yield return [AEGIS128L.MinTagSize, 0, AEGIS128L.NonceSize, AEGIS128L.KeySize - 1, 16, AEGIS128L.MinTagSize];
        yield return [AEGIS128L.MaxTagSize, 0, AEGIS128L.NonceSize, AEGIS128L.KeySize, 16, AEGIS128L.MaxTagSize + 1];
        yield return [AEGIS128L.MaxTagSize, 0, AEGIS128L.NonceSize, AEGIS128L.KeySize, 16, AEGIS128L.MaxTagSize - 1];
        yield return [AEGIS128L.MinTagSize, 0, AEGIS128L.NonceSize, AEGIS128L.KeySize, 16, AEGIS128L.MinTagSize + 1];
        yield return [AEGIS128L.MinTagSize, 0, AEGIS128L.NonceSize, AEGIS128L.KeySize, 16, AEGIS128L.MinTagSize - 1];
    }

    [TestMethod]
    [DynamicData(nameof(ValidTestVectors), DynamicDataSourceType.Method)]
    public void Encrypt_Valid(string ciphertext, string plaintext, string nonce, string key, string associatedData, int tagSize)
    {
        Span<byte> c = stackalloc byte[ciphertext.Length / 2];
        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> a = Convert.FromHexString(associatedData);

        AEGIS128L.Encrypt(c, p, n, k, a, tagSize);

        Assert.AreEqual(ciphertext, Convert.ToHexString(c).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Encrypt_Invalid(int ciphertextSize, int plaintextSize, int nonceSize, int keySize, int associatedDataSize, int tagSize)
    {
        var c = new byte[ciphertextSize];
        var p = new byte[plaintextSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];
        var a = new byte[associatedDataSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => AEGIS128L.Encrypt(c, p, n, k, a, tagSize));
    }

    [TestMethod]
    [DynamicData(nameof(ValidTestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Valid(string ciphertext, string plaintext, string nonce, string key, string associatedData, int tagSize)
    {
        Span<byte> p = stackalloc byte[plaintext.Length / 2];
        Span<byte> c = Convert.FromHexString(ciphertext);
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> a = Convert.FromHexString(associatedData);

        AEGIS128L.Decrypt(p, c, n, k, a, tagSize);

        Assert.AreEqual(plaintext, Convert.ToHexString(p).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(TamperedTestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Tampered(string ciphertext, string nonce, string key, string associatedData, int tagSize)
    {
        var c = Convert.FromHexString(ciphertext);
        var n = Convert.FromHexString(nonce);
        var k = Convert.FromHexString(key);
        var a = Convert.FromHexString(associatedData);
        var p = new byte[c.Length - tagSize];

        Assert.ThrowsException<CryptographicException>(() => AEGIS128L.Decrypt(p, c, n, k, a, tagSize));
        Assert.IsTrue(p.SequenceEqual(new byte[p.Length]));
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Decrypt_Invalid(int ciphertextSize, int plaintextSize, int nonceSize, int keySize, int associatedDataSize, int tagSize)
    {
        var p = new byte[plaintextSize];
        var c = new byte[ciphertextSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];
        var a = new byte[associatedDataSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => AEGIS128L.Decrypt(p, c, n, k, a, tagSize));
    }
}
