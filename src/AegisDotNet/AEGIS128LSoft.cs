using System.Buffers.Binary;
using System.Security.Cryptography;

namespace AegisDotNet;

internal static class AEGIS128LSoft
{
    private static UInt128 S0, S1, S2, S3, S4, S5, S6, S7;

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
        UInt128 c0 = BinaryPrimitives.ReadUInt128BigEndian(c[..16]);
        UInt128 c1 = BinaryPrimitives.ReadUInt128BigEndian(c[16..]);
        UInt128 k = BinaryPrimitives.ReadUInt128BigEndian(key);
        UInt128 n = BinaryPrimitives.ReadUInt128BigEndian(nonce);

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

    private static void Update(UInt128 m0, UInt128 m1)
    {
        UInt128 s0 = AES.Encrypt(S7, S0 ^ m0);
        UInt128 s1 = AES.Encrypt(S0, S1);
        UInt128 s2 = AES.Encrypt(S1, S2);
        UInt128 s3 = AES.Encrypt(S2, S3);
        UInt128 s4 = AES.Encrypt(S3, S4 ^ m1);
        UInt128 s5 = AES.Encrypt(S4, S5);
        UInt128 s6 = AES.Encrypt(S5, S6);
        UInt128 s7 = AES.Encrypt(S6, S7);

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
        UInt128 ad0 = BinaryPrimitives.ReadUInt128BigEndian(associatedData[..16]);
        UInt128 ad1 = BinaryPrimitives.ReadUInt128BigEndian(associatedData[16..]);
        Update(ad0, ad1);
    }

    private static void Enc(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext)
    {
        UInt128 z0 = S6 ^ S1 ^ (S2 & S3);
        UInt128 z1 = S2 ^ S5 ^ (S6 & S7);

        UInt128 t0 = BinaryPrimitives.ReadUInt128BigEndian(plaintext[..16]);
        UInt128 t1 = BinaryPrimitives.ReadUInt128BigEndian(plaintext[16..]);
        UInt128 out0 = t0 ^ z0;
        UInt128 out1 = t1 ^ z1;

        Update(t0, t1);
        BinaryPrimitives.WriteUInt128BigEndian(ciphertext[..16], out0);
        BinaryPrimitives.WriteUInt128BigEndian(ciphertext[16..], out1);
    }

    private static void Dec(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext)
    {
        UInt128 z0 = S6 ^ S1 ^ (S2 & S3);
        UInt128 z1 = S2 ^ S5 ^ (S6 & S7);

        UInt128 t0 = BinaryPrimitives.ReadUInt128BigEndian(ciphertext[..16]);
        UInt128 t1 = BinaryPrimitives.ReadUInt128BigEndian(ciphertext[16..]);
        UInt128 out0 = t0 ^ z0;
        UInt128 out1 = t1 ^ z1;

        Update(out0, out1);
        BinaryPrimitives.WriteUInt128BigEndian(plaintext[..16], out0);
        BinaryPrimitives.WriteUInt128BigEndian(plaintext[16..], out1);
    }

    private static void DecPartial(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext)
    {
        UInt128 z0 = S6 ^ S1 ^ (S2 & S3);
        UInt128 z1 = S2 ^ S5 ^ (S6 & S7);

        Span<byte> pad = stackalloc byte[32];
        ciphertext.CopyTo(pad);
        UInt128 t0 = BinaryPrimitives.ReadUInt128BigEndian(pad[..16]);
        UInt128 t1 = BinaryPrimitives.ReadUInt128BigEndian(pad[16..]);
        UInt128 out0 = t0 ^ z0;
        UInt128 out1 = t1 ^ z1;

        BinaryPrimitives.WriteUInt128BigEndian(pad[..16], out0);
        BinaryPrimitives.WriteUInt128BigEndian(pad[16..], out1);
        pad[..ciphertext.Length].CopyTo(plaintext);

        pad[ciphertext.Length..].Clear();
        UInt128 v0 = BinaryPrimitives.ReadUInt128BigEndian(pad[..16]);
        UInt128 v1 = BinaryPrimitives.ReadUInt128BigEndian(pad[16..]);
        Update(v0, v1);
    }

    private static void Finalize(Span<byte> tag, ulong associatedDataLength, ulong plaintextLength)
    {
        Span<byte> b = stackalloc byte[16];
        BinaryPrimitives.WriteUInt64LittleEndian(b[..8], associatedDataLength * 8);
        BinaryPrimitives.WriteUInt64LittleEndian(b[8..], plaintextLength * 8);

        UInt128 t = S2 ^ BinaryPrimitives.ReadUInt128BigEndian(b);

        for (int i = 0; i < 7; i++) {
            Update(t, t);
        }

        if (tag.Length == 16) {
            UInt128 a = S0 ^ S1 ^ S2 ^ S3 ^ S4 ^ S5 ^ S6;
            BinaryPrimitives.WriteUInt128BigEndian(tag, a);
        }
        else {
            UInt128 a1 = S0 ^ S1 ^ S2 ^ S3;
            UInt128 a2 = S4 ^ S5 ^ S6 ^ S7;
            BinaryPrimitives.WriteUInt128BigEndian(tag[..16], a1);
            BinaryPrimitives.WriteUInt128BigEndian(tag[16..], a2);
        }
    }
}
