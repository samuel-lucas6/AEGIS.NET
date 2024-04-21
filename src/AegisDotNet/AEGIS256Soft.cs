using System.Buffers.Binary;
using System.Security.Cryptography;

namespace AegisDotNet;

internal static class AEGIS256Soft
{
    private static UInt128 S0, S1, S2, S3, S4, S5;

    internal static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default, int tagSize = AEGIS256.MinTagSize)
    {
        Init(key, nonce);

        int i = 0;
        Span<byte> pad = stackalloc byte[16];
        while (i + 16 <= associatedData.Length) {
            Absorb(associatedData.Slice(i, 16));
            i += 16;
        }
        if (associatedData.Length % 16 != 0) {
            pad.Clear();
            associatedData[i..].CopyTo(pad);
            Absorb(pad);
        }

        i = 0;
        while (i + 16 <= plaintext.Length) {
            Enc(ciphertext.Slice(i, 16), plaintext.Slice(i, 16));
            i += 16;
        }
        if (plaintext.Length % 16 != 0) {
            Span<byte> tmp = stackalloc byte[16];
            pad.Clear();
            plaintext[i..].CopyTo(pad);
            Enc(tmp, pad);
            tmp[..(plaintext.Length % 16)].CopyTo(ciphertext[i..^tagSize]);
        }
        CryptographicOperations.ZeroMemory(pad);

        Finalize(ciphertext[^tagSize..], (ulong)associatedData.Length, (ulong)plaintext.Length);
    }

    internal static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default, int tagSize = AEGIS256.MinTagSize)
    {
        Init(key, nonce);

        int i = 0;
        while (i + 16 <= associatedData.Length) {
            Absorb(associatedData.Slice(i, 16));
            i += 16;
        }
        if (associatedData.Length % 16 != 0) {
            Span<byte> pad = stackalloc byte[16];
            pad.Clear();
            associatedData[i..].CopyTo(pad);
            Absorb(pad);
            CryptographicOperations.ZeroMemory(pad);
        }

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
        UInt128 c0 = BinaryPrimitives.ReadUInt128BigEndian(c[..16]);
        UInt128 c1 = BinaryPrimitives.ReadUInt128BigEndian(c[16..]);
        UInt128 k0 = BinaryPrimitives.ReadUInt128BigEndian(key[..16]);
        UInt128 k1 = BinaryPrimitives.ReadUInt128BigEndian(key[16..]);
        UInt128 n0 = BinaryPrimitives.ReadUInt128BigEndian(nonce[..16]);
        UInt128 n1 = BinaryPrimitives.ReadUInt128BigEndian(nonce[16..]);

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

    private static void Update(UInt128 message)
    {
        UInt128 s0 = AES.Encrypt(S5, S0 ^ message);
        UInt128 s1 = AES.Encrypt(S0, S1);
        UInt128 s2 = AES.Encrypt(S1, S2);
        UInt128 s3 = AES.Encrypt(S2, S3);
        UInt128 s4 = AES.Encrypt(S3, S4);
        UInt128 s5 = AES.Encrypt(S4, S5);

        S0 = s0;
        S1 = s1;
        S2 = s2;
        S3 = s3;
        S4 = s4;
        S5 = s5;
    }

    private static void Absorb(ReadOnlySpan<byte> associatedData)
    {
        UInt128 ad = BinaryPrimitives.ReadUInt128BigEndian(associatedData);
        Update(ad);
    }

    private static void Enc(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext)
    {
        UInt128 z = S1 ^ S4 ^ S5 ^ (S2 & S3);
        UInt128 xi = BinaryPrimitives.ReadUInt128BigEndian(plaintext);
        Update(xi);
        UInt128 ci = xi ^ z;
        BinaryPrimitives.WriteUInt128BigEndian(ciphertext, ci);
    }

    private static void Dec(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext)
    {
        UInt128 z = S1 ^ S4 ^ S5 ^ (S2 & S3);
        UInt128 ci = BinaryPrimitives.ReadUInt128BigEndian(ciphertext);
        UInt128 xi = ci ^ z;
        Update(xi);
        BinaryPrimitives.WriteUInt128BigEndian(plaintext, xi);
    }

    private static void DecPartial(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext)
    {
        UInt128 z = S1 ^ S4 ^ S5 ^ (S2 & S3);

        Span<byte> pad = stackalloc byte[16];
        ciphertext.CopyTo(pad);
        UInt128 t = BinaryPrimitives.ReadUInt128BigEndian(pad);
        UInt128 output = t ^ z;

        BinaryPrimitives.WriteUInt128BigEndian(pad, output);
        pad[..ciphertext.Length].CopyTo(plaintext);

        pad[ciphertext.Length..].Clear();
        UInt128 v = BinaryPrimitives.ReadUInt128BigEndian(pad);
        Update(v);
    }

    private static void Finalize(Span<byte> tag, ulong associatedDataLength, ulong plaintextLength)
    {
        Span<byte> b = stackalloc byte[16];
        BinaryPrimitives.WriteUInt64LittleEndian(b[..8], associatedDataLength * 8);
        BinaryPrimitives.WriteUInt64LittleEndian(b[8..], plaintextLength * 8);

        UInt128 t = S3 ^ BinaryPrimitives.ReadUInt128BigEndian(b);

        for (int i = 0; i < 7; i++) {
            Update(t);
        }

        if (tag.Length == 16) {
            UInt128 a = S0 ^ S1 ^ S2 ^ S3 ^ S4 ^ S5;
            BinaryPrimitives.WriteUInt128BigEndian(tag, a);
        }
        else {
            UInt128 a1 = S0 ^ S1 ^ S2;
            UInt128 a2 = S3 ^ S4 ^ S5;
            BinaryPrimitives.WriteUInt128BigEndian(tag[..16], a1);
            BinaryPrimitives.WriteUInt128BigEndian(tag[16..], a2);
        }
    }
}
