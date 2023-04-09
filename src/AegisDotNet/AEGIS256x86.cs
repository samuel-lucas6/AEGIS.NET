using System.Buffers.Binary;
using System.Runtime.Intrinsics;
using System.Security.Cryptography;
using Aes = System.Runtime.Intrinsics.X86.Aes;

namespace AegisDotNet;

internal static class AEGIS256x86
{
    private static Vector128<byte> S0, S1, S2, S3, S4, S5;
    
    internal static bool IsSupported() => Aes.IsSupported;
    
    internal static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default, int tagSize = AEGIS256.MinTagSize)
    {
        Init(key, nonce);
        
        int i = 0;
        Span<byte> tmp = stackalloc byte[16];
        while (i + 16 <= associatedData.Length) {
            Enc(tmp, associatedData.Slice(i, 16));
            i += 16;
        }
        if (associatedData.Length % 16 != 0) {
            Span<byte> pad = stackalloc byte[16]; pad.Clear();
            associatedData[i..].CopyTo(pad);
            Enc(tmp, pad);
            CryptographicOperations.ZeroMemory(pad);
        }
        
        i = 0;
        while (i + 16 <= plaintext.Length) {
            Enc(ciphertext.Slice(i, 16), plaintext.Slice(i, 16));
            i += 16;
        }
        if (plaintext.Length % 16 != 0) {
            Span<byte> pad = stackalloc byte[16]; pad.Clear();
            plaintext[i..].CopyTo(pad);
            Enc(tmp, pad);
            tmp[..(plaintext.Length % 16)].CopyTo(ciphertext[i..^tagSize]);
            CryptographicOperations.ZeroMemory(pad);
        }
        CryptographicOperations.ZeroMemory(tmp);
        
        Finalize(ciphertext[^tagSize..], (ulong)associatedData.Length, (ulong)plaintext.Length);
    }
    
    internal static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default, int tagSize = AEGIS256.MinTagSize)
    {
        Init(key, nonce);
        
        int i = 0;
        Span<byte> tmp = stackalloc byte[16];
        while (i + 16 <= associatedData.Length) {
            Enc(tmp, associatedData.Slice(i, 16));
            i += 16;
        }
        if (associatedData.Length % 16 != 0) {
            Span<byte> pad = stackalloc byte[16]; pad.Clear();
            associatedData[i..].CopyTo(pad);
            Enc(tmp, pad);
            CryptographicOperations.ZeroMemory(pad);
        }
        CryptographicOperations.ZeroMemory(tmp);
        
        i = 0;
        while (i + 16 <= ciphertext.Length - tagSize) {
            Dec(plaintext.Slice(i, 16), ciphertext.Slice(i, 16));
            i += 16;
        }
        if ((ciphertext.Length - tagSize) % 16 != 0) {
            DecPartial(plaintext[i..], ciphertext[i..^tagSize]);
        }
        
        Span<byte> tag = stackalloc byte[tagSize];
        Finalize(tag, (ulong)associatedData.Length, (ulong)plaintext.Length);
        
        if (!CryptographicOperations.FixedTimeEquals(tag, ciphertext[^tagSize..])) {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(tag);
            throw new CryptographicException();
        }
    }
    
    private static void Init(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce)
    {
        ReadOnlySpan<byte> c = stackalloc byte[]
        {
            0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62,
            0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd
        };
        Vector128<byte> c0 = Vector128.Create(c[..16]);
        Vector128<byte> c1 = Vector128.Create(c[16..]);
        Vector128<byte> k0 = Vector128.Create(key[..16]);
        Vector128<byte> k1 = Vector128.Create(key[16..]);
        Vector128<byte> n0 = Vector128.Create(nonce[..16]);
        Vector128<byte> n1 = Vector128.Create(nonce[16..]);
        
        S0 = k0 ^ n0;
        S1 = k1 ^ n1;
        S2 = c1;
        S3 = c0;
        S4 = k0 ^ c0;
        S5 = k1 ^ c1;
        
        for (int i = 0; i < 4; i++) {
            Update(k0);
            Update(k1);
            Update(k0 ^ n0);
            Update(k1 ^ n1);
        }
    }
    
    private static void Update(Vector128<byte> message)
    {
        Vector128<byte> s0 = Aes.Encrypt(S5, S0 ^ message);
        Vector128<byte> s1 = Aes.Encrypt(S0, S1);
        Vector128<byte> s2 = Aes.Encrypt(S1, S2);
        Vector128<byte> s3 = Aes.Encrypt(S2, S3);
        Vector128<byte> s4 = Aes.Encrypt(S3, S4);
        Vector128<byte> s5 = Aes.Encrypt(S4, S5);
        
        S0 = s0;
        S1 = s1;
        S2 = s2;
        S3 = s3;
        S4 = s4;
        S5 = s5;
    }
    
    private static void Enc(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext)
    {
        Vector128<byte> z = S1 ^ S4 ^ S5 ^ (S2 & S3);
        Vector128<byte> xi = Vector128.Create(plaintext);
        Update(xi);
        Vector128<byte> ci = xi ^ z;
        ci.CopyTo(ciphertext);
    }
    
    private static void Dec(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext)
    {
        Vector128<byte> z = S1 ^ S4 ^ S5 ^ (S2 & S3);
        Vector128<byte> ci = Vector128.Create(ciphertext);
        Vector128<byte> xi = ci ^ z;
        Update(xi);
        xi.CopyTo(plaintext);
    }
    
    private static void DecPartial(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext)
    {
        Vector128<byte> z = S1 ^ S4 ^ S5 ^ (S2 & S3);
        
        var pad = new byte[16];
        ciphertext.CopyTo(pad);
        Vector128<byte> t = Vector128.Create(pad);
        Vector128<byte> output = t ^ z;
        
        output.CopyTo(pad);
        pad[..ciphertext.Length].CopyTo(plaintext);
        
        pad.AsSpan()[ciphertext.Length..].Clear();
        Vector128<byte> v = Vector128.Create(pad);
        Update(v);
    }
    
    private static void Finalize(Span<byte> tag, ulong associatedDataLength, ulong messageLength)
    {
        var b = new byte[16];
        BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan()[..8], associatedDataLength * 8);
        BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan()[8..], messageLength * 8);
        
        Vector128<byte> t = S3 ^ Vector128.Create(b);
        
        for (int i = 0; i < 7; i++) {
            Update(t);
        }
        
        if (tag.Length == 16) {
            Vector128<byte> a = S0 ^ S1 ^ S2 ^ S3 ^ S4 ^ S5;
            a.CopyTo(tag);
        }
        else {
            Vector128<byte> a1 = S0 ^ S1 ^ S2;
            Vector128<byte> a2 = S3 ^ S4 ^ S5;
            a1.CopyTo(tag[..16]);
            a2.CopyTo(tag[16..]);
        }
    }
}