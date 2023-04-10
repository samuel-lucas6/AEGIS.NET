using AegisDotNet;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace AegisDotNetTests;

[TestClass]
public class AEGIS256Tests
{
    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-aegis-aead#appendix-A.3
    public static IEnumerable<object[]> ValidTestVectors()
    {
        // Test Vector 1
        yield return new object[]
        {
            "754fc3d8c973246dcc6d741412a4b2363fe91994768b332ed7f570a19ec5896e",
            "00000000000000000000000000000000",
            "1000020000000000000000000000000000000000000000000000000000000000",
            "1001000000000000000000000000000000000000000000000000000000000000",
            "",
            AEGIS256.MinTagSize
        };
        yield return new object[]
        {
            "754fc3d8c973246dcc6d741412a4b2361181a1d18091082bf0266f66297d167d2e68b845f61a3b0527d31fc7b7b89f13",
            "00000000000000000000000000000000",
            "1000020000000000000000000000000000000000000000000000000000000000",
            "1001000000000000000000000000000000000000000000000000000000000000",
            "",
            AEGIS256.MaxTagSize
        };
        // Test Vector 2
        yield return new object[]
        {
            "e3def978a0f054afd1e761d7553afba3",
            "",
            "1000020000000000000000000000000000000000000000000000000000000000",
            "1001000000000000000000000000000000000000000000000000000000000000",
            "",
            AEGIS256.MinTagSize
        };
        yield return new object[]
        {
            "6a348c930adbd654896e1666aad67de989ea75ebaa2b82fb588977b1ffec864a",
            "",
            "1000020000000000000000000000000000000000000000000000000000000000",
            "1001000000000000000000000000000000000000000000000000000000000000",
            "",
            AEGIS256.MaxTagSize
        };
        // Test Vector 3
        yield return new object[]
        {
            "f373079ed84b2709faee373584585d60accd191db310ef5d8b11833df9dec7118d86f91ee606e9ff26a01b64ccbdd91d",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "1000020000000000000000000000000000000000000000000000000000000000",
            "1001000000000000000000000000000000000000000000000000000000000000",
            "0001020304050607",
            AEGIS256.MinTagSize
        };
        yield return new object[]
        {
            "f373079ed84b2709faee373584585d60accd191db310ef5d8b11833df9dec711b7d28d0c3c0ebd409fd22b44160503073a547412da0854bfb9723020dab8da1a",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "1000020000000000000000000000000000000000000000000000000000000000",
            "1001000000000000000000000000000000000000000000000000000000000000",
            "0001020304050607",
            AEGIS256.MaxTagSize
        };
        // Test Vector 4
        yield return new object[]
        {
            "f373079ed84b2709faee37358458c60b9c2d33ceb058f96e6dd03c215652",
            "000102030405060708090a0b0c0d",
            "1000020000000000000000000000000000000000000000000000000000000000",
            "1001000000000000000000000000000000000000000000000000000000000000",
            "0001020304050607",
            AEGIS256.MinTagSize
        };
        yield return new object[]
        {
            "f373079ed84b2709faee373584588c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9",
            "000102030405060708090a0b0c0d",
            "1000020000000000000000000000000000000000000000000000000000000000",
            "1001000000000000000000000000000000000000000000000000000000000000",
            "0001020304050607",
            AEGIS256.MaxTagSize
        };
        // Test Vector 5
        yield return new object[]
        {
            "57754a7d09963e7c787583a2e7b859bb24fa1e04d49fd550b2511a358e3bca252a9b1b8b30cc4a67ab8a7d53fd0e98d727accca94925e128",
            "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637",
            "1000020000000000000000000000000000000000000000000000000000000000",
            "1001000000000000000000000000000000000000000000000000000000000000",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829",
            AEGIS256.MinTagSize
        };
        yield return new object[]
        {
            "57754a7d09963e7c787583a2e7b859bb24fa1e04d49fd550b2511a358e3bca252a9b1b8b30cc4a67a3aca270c006094d71c20e6910b5161c0826df233d08919a566ec2c05990f734",
            "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637",
            "1000020000000000000000000000000000000000000000000000000000000000",
            "1001000000000000000000000000000000000000000000000000000000000000",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829",
            AEGIS256.MaxTagSize
        };
    }
    
    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-aegis-aead#appendix-A.3.7
    public static IEnumerable<object[]> TamperedTestVectors()
    {
        // Test Vector 6
        yield return new object[]
        {
            "f373079ed84b2709faee37358458c60b9c2d33ceb058f96e6dd03c215652",
            "1001000000000000000000000000000000000000000000000000000000000000",
            "1000020000000000000000000000000000000000000000000000000000000000",
            "0001020304050607",
            AEGIS256.MinTagSize
        };
        yield return new object[]
        {
            "f373079ed84b2709faee373584588c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9",
            "1001000000000000000000000000000000000000000000000000000000000000",
            "1000020000000000000000000000000000000000000000000000000000000000",
            "0001020304050607",
            AEGIS256.MaxTagSize
        };
        // Test Vector 7
        yield return new object[]
        {
            "f373079ed84b2709faee37358459c60b9c2d33ceb058f96e6dd03c215652",
            "1000020000000000000000000000000000000000000000000000000000000000",
            "1001000000000000000000000000000000000000000000000000000000000000",
            "0001020304050607",
            AEGIS256.MinTagSize
        };
        yield return new object[]
        {
            "f373079ed84b2709faee373584598c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9",
            "1000020000000000000000000000000000000000000000000000000000000000",
            "1001000000000000000000000000000000000000000000000000000000000000",
            "0001020304050607",
            AEGIS256.MaxTagSize
        };
        // Test Vector 8
        yield return new object[]
        {
            "f373079ed84b2709faee37358458c60b9c2d33ceb058f96e6dd03c215652",
            "1000020000000000000000000000000000000000000000000000000000000000",
            "1001000000000000000000000000000000000000000000000000000000000000",
            "0001020304050608",
            AEGIS256.MinTagSize
        };
        yield return new object[]
        {
            "f373079ed84b2709faee373584588c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9",
            "1000020000000000000000000000000000000000000000000000000000000000",
            "1001000000000000000000000000000000000000000000000000000000000000",
            "0001020304050608",
            AEGIS256.MaxTagSize
        };
        // Test Vector 9
        yield return new object[]
        {
            "f373079ed84b2709faee37358458c60b9c2d33ceb058f96e6dd03c215653",
            "1000020000000000000000000000000000000000000000000000000000000000",
            "1001000000000000000000000000000000000000000000000000000000000000",
            "0001020304050607",
            AEGIS256.MinTagSize
        };
        yield return new object[]
        {
            "f373079ed84b2709faee373584588c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2da",
            "1000020000000000000000000000000000000000000000000000000000000000",
            "1001000000000000000000000000000000000000000000000000000000000000",
            "0001020304050607",
            AEGIS256.MaxTagSize
        };
    }
    
    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return new object[] { AEGIS256.MinTagSize, 1, AEGIS256.NonceSize, AEGIS256.KeySize, 16, AEGIS256.MinTagSize };
        yield return new object[] { AEGIS256.MinTagSize, 0, AEGIS256.NonceSize + 1, AEGIS256.KeySize, 16, AEGIS256.MinTagSize };
        yield return new object[] { AEGIS256.MinTagSize, 0, AEGIS256.NonceSize - 1, AEGIS256.KeySize, 16, AEGIS256.MinTagSize };
        yield return new object[] { AEGIS256.MinTagSize, 0, AEGIS256.NonceSize, AEGIS256.KeySize + 1, 16, AEGIS256.MinTagSize };
        yield return new object[] { AEGIS256.MinTagSize, 0, AEGIS256.NonceSize, AEGIS256.KeySize - 1, 16, AEGIS256.MinTagSize };
        yield return new object[] { AEGIS256.MaxTagSize, 0, AEGIS256.NonceSize, AEGIS256.KeySize, 16, AEGIS256.MaxTagSize + 1 };
        yield return new object[] { AEGIS256.MaxTagSize, 0, AEGIS256.NonceSize, AEGIS256.KeySize, 16, AEGIS256.MaxTagSize - 1 };
        yield return new object[] { AEGIS256.MinTagSize, 0, AEGIS256.NonceSize, AEGIS256.KeySize, 16, AEGIS256.MinTagSize + 1 };
        yield return new object[] { AEGIS256.MinTagSize, 0, AEGIS256.NonceSize, AEGIS256.KeySize, 16, AEGIS256.MinTagSize - 1 };
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
        
        AEGIS256.Encrypt(c, p, n, k, a, tagSize);
        
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
        
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => AEGIS256.Encrypt(c, p, n, k, a, tagSize));
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
        
        AEGIS256.Decrypt(p, c, n, k, a, tagSize);
        
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
        
        Assert.ThrowsException<CryptographicException>(() => AEGIS256.Decrypt(p, c, n, k, a, tagSize));
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
        
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => AEGIS256.Decrypt(p, c, n, k, a, tagSize));
    }
}