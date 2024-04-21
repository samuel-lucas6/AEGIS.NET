using System.Buffers.Binary;
using System.Runtime.Intrinsics;
using System.Security.Cryptography;
using Aes = System.Runtime.Intrinsics.Arm.Aes;

namespace AegisDotNet;

internal static class AEGIS128LArm
{
    private static Vector128<byte> S0, S1, S2, S3, S4, S5, S6, S7;

    internal static bool IsSupported() => Aes.IsSupported;

    internal static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default, int tagSize = AEGIS128L.MinTagSize)
    {
        Init(key, nonce);

        int i = 0;
        Span<byte> pad = stackalloc byte[32];
        while (i + 32 <= associatedData.Length) {
            Absorb(associatedData.Slice(i, 32));
            i += 32;
        }
        if (associatedData.Length % 32 != 0) {
            pad.Clear();
            associatedData[i..].CopyTo(pad);
            Absorb(pad);
        }

        i = 0;
        while (i + 32 <= plaintext.Length) {
            Enc(ciphertext.Slice(i, 32), plaintext.Slice(i, 32));
            i += 32;
        }
        if (plaintext.Length % 32 != 0) {
            Span<byte> tmp = stackalloc byte[32];
            pad.Clear();
            plaintext[i..].CopyTo(pad);
            Enc(tmp, pad);
            tmp[..(plaintext.Length % 32)].CopyTo(ciphertext[i..^tagSize]);
        }
        CryptographicOperations.ZeroMemory(pad);

        Finalize(ciphertext[^tagSize..], (ulong)associatedData.Length, (ulong)plaintext.Length);
    }

    internal static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default, int tagSize = AEGIS128L.MinTagSize)
    {
        Init(key, nonce);

        int i = 0;
        while (i + 32 <= associatedData.Length) {
            Absorb(associatedData.Slice(i, 32));
            i += 32;
        }
        if (associatedData.Length % 32 != 0) {
            Span<byte> pad = stackalloc byte[32];
            pad.Clear();
            associatedData[i..].CopyTo(pad);
            Absorb(pad);
            CryptographicOperations.ZeroMemory(pad);
        }

        i = 0;
        while (i + 32 <= ciphertext.Length - tagSize) {
            Dec(plaintext.Slice(i, 32), ciphertext.Slice(i, 32));
            i += 32;
        }
        if ((ciphertext.Length - tagSize) % 32 != 0) {
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
        Vector128<byte> k = Vector128.Create(key);
        Vector128<byte> n = Vector128.Create(nonce);

        S0 = k ^ n;
        S1 = c1;
        S2 = c0;
        S3 = c1;
        S4 = k ^ n;
        S5 = k ^ c0;
        S6 = k ^ c1;
        S7 = k ^ c0;

        for (int i = 0; i < 10; i++) {
            Update(n, k);
        }
    }

    private static void Update(Vector128<byte> m0, Vector128<byte> m1)
    {
        Vector128<byte> s0 = Aes.Encrypt(S7, S0 ^ m0);
        Vector128<byte> s1 = Aes.Encrypt(S0, S1);
        Vector128<byte> s2 = Aes.Encrypt(S1, S2);
        Vector128<byte> s3 = Aes.Encrypt(S2, S3);
        Vector128<byte> s4 = Aes.Encrypt(S3, S4 ^ m1);
        Vector128<byte> s5 = Aes.Encrypt(S4, S5);
        Vector128<byte> s6 = Aes.Encrypt(S5, S6);
        Vector128<byte> s7 = Aes.Encrypt(S6, S7);

        S0 = s0;
        S1 = s1;
        S2 = s2;
        S3 = s3;
        S4 = s4;
        S5 = s5;
        S6 = s6;
        S7 = s7;
    }

    private static void Absorb(ReadOnlySpan<byte> associatedData)
    {
        Vector128<byte> ad0 = Vector128.Create(associatedData[..16]);
        Vector128<byte> ad1 = Vector128.Create(associatedData[16..]);
        Update(ad0, ad1);
    }

    private static void Enc(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext)
    {
        Vector128<byte> z0 = S6 ^ S1 ^ (S2 & S3);
        Vector128<byte> z1 = S2 ^ S5 ^ (S6 & S7);

        Vector128<byte> t0 = Vector128.Create(plaintext[..16]);
        Vector128<byte> t1 = Vector128.Create(plaintext[16..]);
        Vector128<byte> out0 = t0 ^ z0;
        Vector128<byte> out1 = t1 ^ z1;

        Update(t0, t1);
        out0.CopyTo(ciphertext[..16]);
        out1.CopyTo(ciphertext[16..]);
    }

    private static void Dec(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext)
    {
        Vector128<byte> z0 = S6 ^ S1 ^ (S2 & S3);
        Vector128<byte> z1 = S2 ^ S5 ^ (S6 & S7);

        Vector128<byte> t0 = Vector128.Create(ciphertext[..16]);
        Vector128<byte> t1 = Vector128.Create(ciphertext[16..]);
        Vector128<byte> out0 = t0 ^ z0;
        Vector128<byte> out1 = t1 ^ z1;

        Update(out0, out1);
        out0.CopyTo(plaintext[..16]);
        out1.CopyTo(plaintext[16..]);
    }

    private static void DecPartial(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext)
    {
        Vector128<byte> z0 = S6 ^ S1 ^ (S2 & S3);
        Vector128<byte> z1 = S2 ^ S5 ^ (S6 & S7);

        var pad = new byte[32];
        ciphertext.CopyTo(pad);
        Vector128<byte> t0 = Vector128.Create(pad[..16]);
        Vector128<byte> t1 = Vector128.Create(pad[16..]);
        Vector128<byte> out0 = t0 ^ z0;
        Vector128<byte> out1 = t1 ^ z1;

        Span<byte> p = pad;
        out0.CopyTo(p[..16]);
        out1.CopyTo(p[16..]);
        p[..ciphertext.Length].CopyTo(plaintext);

        p[ciphertext.Length..].Clear();
        Vector128<byte> v0 = Vector128.Create(pad[..16]);
        Vector128<byte> v1 = Vector128.Create(pad[16..]);
        Update(v0, v1);
    }

    private static void Finalize(Span<byte> tag, ulong associatedDataLength, ulong plaintextLength)
    {
        var b = new byte[16]; Span<byte> bb = b;
        BinaryPrimitives.WriteUInt64LittleEndian(bb[..8], associatedDataLength * 8);
        BinaryPrimitives.WriteUInt64LittleEndian(bb[8..], plaintextLength * 8);

        Vector128<byte> t = S2 ^ Vector128.Create(b);

        for (int i = 0; i < 7; i++) {
            Update(t, t);
        }

        if (tag.Length == 16) {
            Vector128<byte> a = S0 ^ S1 ^ S2 ^ S3 ^ S4 ^ S5 ^ S6;
            a.CopyTo(tag);
        }
        else {
            Vector128<byte> a1 = S0 ^ S1 ^ S2 ^ S3;
            Vector128<byte> a2 = S4 ^ S5 ^ S6 ^ S7;
            a1.CopyTo(tag[..16]);
            a2.CopyTo(tag[16..]);
        }
    }
}
