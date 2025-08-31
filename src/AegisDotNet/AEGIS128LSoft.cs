using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;

namespace AegisDotNet;

internal sealed class AEGIS128LSoft : IDisposable
{
    private readonly UInt128[] _s = new UInt128[8];
    private GCHandle _handle;
    private bool _disposed;

    internal AEGIS128LSoft(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce)
    {
        _handle = GCHandle.Alloc(_s, GCHandleType.Pinned);
        ReadOnlySpan<byte> c =
        [
            0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62,
            0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd
        ];
        UInt128 c0 = BinaryPrimitives.ReadUInt128BigEndian(c[..16]);
        UInt128 c1 = BinaryPrimitives.ReadUInt128BigEndian(c[16..]);
        UInt128 k = BinaryPrimitives.ReadUInt128BigEndian(key);
        UInt128 n = BinaryPrimitives.ReadUInt128BigEndian(nonce);

        _s[0] = k ^ n;
        _s[1] = c1;
        _s[2] = c0;
        _s[3] = c1;
        _s[4] = k ^ n;
        _s[5] = k ^ c0;
        _s[6] = k ^ c1;
        _s[7] = k ^ c0;

        for (int i = 0; i < 10; i++) {
            Update(n, k);
        }
    }

    internal void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData = default, int tagSize = AEGIS128L.MinTagSize)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(AEGIS128LSoft)); }
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

    internal void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> associatedData = default, int tagSize = AEGIS128L.MinTagSize)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(AEGIS128LSoft)); }
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

    private void Update(UInt128 m0, UInt128 m1)
    {
        UInt128 s0 = AES.Encrypt(_s[7], _s[0] ^ m0);
        UInt128 s1 = AES.Encrypt(_s[0], _s[1]);
        UInt128 s2 = AES.Encrypt(_s[1], _s[2]);
        UInt128 s3 = AES.Encrypt(_s[2], _s[3]);
        UInt128 s4 = AES.Encrypt(_s[3], _s[4] ^ m1);
        UInt128 s5 = AES.Encrypt(_s[4], _s[5]);
        UInt128 s6 = AES.Encrypt(_s[5], _s[6]);
        UInt128 s7 = AES.Encrypt(_s[6], _s[7]);

        _s[0] = s0;
        _s[1] = s1;
        _s[2] = s2;
        _s[3] = s3;
        _s[4] = s4;
        _s[5] = s5;
        _s[6] = s6;
        _s[7] = s7;
    }

    private void Absorb(ReadOnlySpan<byte> associatedData)
    {
        UInt128 ad0 = BinaryPrimitives.ReadUInt128BigEndian(associatedData[..16]);
        UInt128 ad1 = BinaryPrimitives.ReadUInt128BigEndian(associatedData[16..]);
        Update(ad0, ad1);
    }

    private void Enc(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext)
    {
        UInt128 z0 = _s[6] ^ _s[1] ^ (_s[2] & _s[3]);
        UInt128 z1 = _s[2] ^ _s[5] ^ (_s[6] & _s[7]);

        UInt128 t0 = BinaryPrimitives.ReadUInt128BigEndian(plaintext[..16]);
        UInt128 t1 = BinaryPrimitives.ReadUInt128BigEndian(plaintext[16..]);
        UInt128 out0 = t0 ^ z0;
        UInt128 out1 = t1 ^ z1;

        Update(t0, t1);
        BinaryPrimitives.WriteUInt128BigEndian(ciphertext[..16], out0);
        BinaryPrimitives.WriteUInt128BigEndian(ciphertext[16..], out1);
    }

    private void Dec(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext)
    {
        UInt128 z0 = _s[6] ^ _s[1] ^ (_s[2] & _s[3]);
        UInt128 z1 = _s[2] ^ _s[5] ^ (_s[6] & _s[7]);

        UInt128 t0 = BinaryPrimitives.ReadUInt128BigEndian(ciphertext[..16]);
        UInt128 t1 = BinaryPrimitives.ReadUInt128BigEndian(ciphertext[16..]);
        UInt128 out0 = t0 ^ z0;
        UInt128 out1 = t1 ^ z1;

        Update(out0, out1);
        BinaryPrimitives.WriteUInt128BigEndian(plaintext[..16], out0);
        BinaryPrimitives.WriteUInt128BigEndian(plaintext[16..], out1);
    }

    private void DecPartial(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext)
    {
        UInt128 z0 = _s[6] ^ _s[1] ^ (_s[2] & _s[3]);
        UInt128 z1 = _s[2] ^ _s[5] ^ (_s[6] & _s[7]);

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

    private void Finalize(Span<byte> tag, ulong associatedDataLength, ulong plaintextLength)
    {
        Span<byte> b = stackalloc byte[16];
        BinaryPrimitives.WriteUInt64LittleEndian(b[..8], associatedDataLength * 8);
        BinaryPrimitives.WriteUInt64LittleEndian(b[8..], plaintextLength * 8);

        UInt128 t = _s[2] ^ BinaryPrimitives.ReadUInt128BigEndian(b);

        for (int i = 0; i < 7; i++) {
            Update(t, t);
        }

        if (tag.Length == 16) {
            UInt128 a = _s[0] ^ _s[1] ^ _s[2] ^ _s[3] ^ _s[4] ^ _s[5] ^ _s[6];
            BinaryPrimitives.WriteUInt128BigEndian(tag, a);
        }
        else {
            UInt128 a1 = _s[0] ^ _s[1] ^ _s[2] ^ _s[3];
            UInt128 a2 = _s[4] ^ _s[5] ^ _s[6] ^ _s[7];
            BinaryPrimitives.WriteUInt128BigEndian(tag[..16], a1);
            BinaryPrimitives.WriteUInt128BigEndian(tag[16..], a2);
        }
    }

    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public void Dispose()
    {
        if (_disposed) { return; }
        for (int i = 0; i < _s.Length; i++) {
            _s[i] = 0;
        }
        _handle.Free();
        _disposed = true;
    }
}
