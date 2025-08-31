using System.Buffers.Binary;
using System.Runtime.Intrinsics;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using Aes = System.Runtime.Intrinsics.Arm.Aes;

namespace AegisDotNet;

internal sealed class AEGIS128LArm : IDisposable
{
    private readonly Vector128<byte>[] _s = new Vector128<byte>[8];
    private GCHandle _handle;
    private bool _disposed;

    internal static bool IsSupported() => Aes.IsSupported;

    internal AEGIS128LArm(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce)
    {
        _handle = GCHandle.Alloc(_s, GCHandleType.Pinned);
        ReadOnlySpan<byte> c =
        [
            0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62,
            0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd
        ];
        Vector128<byte> c0 = Vector128.Create(c[..16]);
        Vector128<byte> c1 = Vector128.Create(c[16..]);
        Vector128<byte> k = Vector128.Create(key);
        Vector128<byte> n = Vector128.Create(nonce);

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
        if (_disposed) { throw new ObjectDisposedException(nameof(AEGIS128LArm)); }
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
        if (_disposed) { throw new ObjectDisposedException(nameof(AEGIS128LArm)); }
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

    private void Update(Vector128<byte> m0, Vector128<byte> m1)
    {
        Vector128<byte> s0 = Aes.MixColumns(Aes.Encrypt(_s[7], Vector128<byte>.Zero)) ^ _s[0] ^ m0;
        Vector128<byte> s1 = Aes.MixColumns(Aes.Encrypt(_s[0], Vector128<byte>.Zero)) ^ _s[1];
        Vector128<byte> s2 = Aes.MixColumns(Aes.Encrypt(_s[1], Vector128<byte>.Zero)) ^ _s[2];
        Vector128<byte> s3 = Aes.MixColumns(Aes.Encrypt(_s[2], Vector128<byte>.Zero)) ^ _s[3];
        Vector128<byte> s4 = Aes.MixColumns(Aes.Encrypt(_s[3], Vector128<byte>.Zero)) ^ _s[4] ^ m1;
        Vector128<byte> s5 = Aes.MixColumns(Aes.Encrypt(_s[4], Vector128<byte>.Zero)) ^ _s[5];
        Vector128<byte> s6 = Aes.MixColumns(Aes.Encrypt(_s[5], Vector128<byte>.Zero)) ^ _s[6];
        Vector128<byte> s7 = Aes.MixColumns(Aes.Encrypt(_s[6], Vector128<byte>.Zero)) ^ _s[7];

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
        Vector128<byte> ad0 = Vector128.Create(associatedData[..16]);
        Vector128<byte> ad1 = Vector128.Create(associatedData[16..]);
        Update(ad0, ad1);
    }

    private void Enc(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext)
    {
        Vector128<byte> z0 = _s[6] ^ _s[1] ^ (_s[2] & _s[3]);
        Vector128<byte> z1 = _s[2] ^ _s[5] ^ (_s[6] & _s[7]);

        Vector128<byte> t0 = Vector128.Create(plaintext[..16]);
        Vector128<byte> t1 = Vector128.Create(plaintext[16..]);
        Vector128<byte> out0 = t0 ^ z0;
        Vector128<byte> out1 = t1 ^ z1;

        Update(t0, t1);
        out0.CopyTo(ciphertext[..16]);
        out1.CopyTo(ciphertext[16..]);
    }

    private void Dec(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext)
    {
        Vector128<byte> z0 = _s[6] ^ _s[1] ^ (_s[2] & _s[3]);
        Vector128<byte> z1 = _s[2] ^ _s[5] ^ (_s[6] & _s[7]);

        Vector128<byte> t0 = Vector128.Create(ciphertext[..16]);
        Vector128<byte> t1 = Vector128.Create(ciphertext[16..]);
        Vector128<byte> out0 = t0 ^ z0;
        Vector128<byte> out1 = t1 ^ z1;

        Update(out0, out1);
        out0.CopyTo(plaintext[..16]);
        out1.CopyTo(plaintext[16..]);
    }

    private void DecPartial(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext)
    {
        Vector128<byte> z0 = _s[6] ^ _s[1] ^ (_s[2] & _s[3]);
        Vector128<byte> z1 = _s[2] ^ _s[5] ^ (_s[6] & _s[7]);

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

    private void Finalize(Span<byte> tag, ulong associatedDataLength, ulong plaintextLength)
    {
        var b = new byte[16]; Span<byte> bb = b;
        BinaryPrimitives.WriteUInt64LittleEndian(bb[..8], associatedDataLength * 8);
        BinaryPrimitives.WriteUInt64LittleEndian(bb[8..], plaintextLength * 8);

        Vector128<byte> t = _s[2] ^ Vector128.Create(b);

        for (int i = 0; i < 7; i++) {
            Update(t, t);
        }

        if (tag.Length == 16) {
            Vector128<byte> a = _s[0] ^ _s[1] ^ _s[2] ^ _s[3] ^ _s[4] ^ _s[5] ^ _s[6];
            a.CopyTo(tag);
        }
        else {
            Vector128<byte> a1 = _s[0] ^ _s[1] ^ _s[2] ^ _s[3];
            Vector128<byte> a2 = _s[4] ^ _s[5] ^ _s[6] ^ _s[7];
            a1.CopyTo(tag[..16]);
            a2.CopyTo(tag[16..]);
        }
    }

    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public void Dispose()
    {
        if (_disposed) { return; }
        for (int i = 0; i < _s.Length; i++) {
            _s[i] = Vector128<byte>.Zero;
        }
        _handle.Free();
        _disposed = true;
    }
}
