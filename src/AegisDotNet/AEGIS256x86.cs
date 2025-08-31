using System.Buffers.Binary;
using System.Runtime.Intrinsics;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using Aes = System.Runtime.Intrinsics.X86.Aes;

namespace AegisDotNet;

internal sealed class AEGIS256x86 : IDisposable
{
    private readonly Vector128<byte>[] _s = new Vector128<byte>[6];
    private GCHandle _handle;
    private bool _disposed;

    internal static bool IsSupported() => Aes.IsSupported;

    internal AEGIS256x86(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce)
    {
        _handle = GCHandle.Alloc(_s, GCHandleType.Pinned);
        ReadOnlySpan<byte> c =
        [
            0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62,
            0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd
        ];
        Vector128<byte> c0 = Vector128.Create(c[..16]);
        Vector128<byte> c1 = Vector128.Create(c[16..]);
        Vector128<byte> k0 = Vector128.Create(key[..16]);
        Vector128<byte> k1 = Vector128.Create(key[16..]);
        Vector128<byte> n0 = Vector128.Create(nonce[..16]);
        Vector128<byte> n1 = Vector128.Create(nonce[16..]);

        _s[0] = k0 ^ n0;
        _s[1] = k1 ^ n1;
        _s[2] = c1;
        _s[3] = c0;
        _s[4] = k0 ^ c0;
        _s[5] = k1 ^ c1;

        for (int i = 0; i < 4; i++) {
            Update(k0);
            Update(k1);
            Update(k0 ^ n0);
            Update(k1 ^ n1);
        }
    }

    internal void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData = default, int tagSize = AEGIS256.MinTagSize)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(AEGIS256x86)); }
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

    internal void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> associatedData = default, int tagSize = AEGIS256.MinTagSize)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(AEGIS256x86)); }
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

    private void Update(Vector128<byte> message)
    {
        Vector128<byte> s0 = Aes.Encrypt(_s[5], _s[0] ^ message);
        Vector128<byte> s1 = Aes.Encrypt(_s[0], _s[1]);
        Vector128<byte> s2 = Aes.Encrypt(_s[1], _s[2]);
        Vector128<byte> s3 = Aes.Encrypt(_s[2], _s[3]);
        Vector128<byte> s4 = Aes.Encrypt(_s[3], _s[4]);
        Vector128<byte> s5 = Aes.Encrypt(_s[4], _s[5]);

        _s[0] = s0;
        _s[1] = s1;
        _s[2] = s2;
        _s[3] = s3;
        _s[4] = s4;
        _s[5] = s5;
    }

    private void Absorb(ReadOnlySpan<byte> associatedData)
    {
        Vector128<byte> ad = Vector128.Create(associatedData);
        Update(ad);
    }

    private void Enc(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext)
    {
        Vector128<byte> z = _s[1] ^ _s[4] ^ _s[5] ^ (_s[2] & _s[3]);
        Vector128<byte> xi = Vector128.Create(plaintext);
        Update(xi);
        Vector128<byte> ci = xi ^ z;
        ci.CopyTo(ciphertext);
    }

    private void Dec(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext)
    {
        Vector128<byte> z = _s[1] ^ _s[4] ^ _s[5] ^ (_s[2] & _s[3]);
        Vector128<byte> ci = Vector128.Create(ciphertext);
        Vector128<byte> xi = ci ^ z;
        Update(xi);
        xi.CopyTo(plaintext);
    }

    private void DecPartial(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext)
    {
        Vector128<byte> z = _s[1] ^ _s[4] ^ _s[5] ^ (_s[2] & _s[3]);

        var pad = new byte[16];
        ciphertext.CopyTo(pad);
        Vector128<byte> t = Vector128.Create(pad);
        Vector128<byte> output = t ^ z;

        Span<byte> p = pad;
        output.CopyTo(p);
        p[..ciphertext.Length].CopyTo(plaintext);

        p[ciphertext.Length..].Clear();
        Vector128<byte> v = Vector128.Create(pad);
        Update(v);
    }

    private void Finalize(Span<byte> tag, ulong associatedDataLength, ulong plaintextLength)
    {
        var b = new byte[16]; Span<byte> bb = b;
        BinaryPrimitives.WriteUInt64LittleEndian(bb[..8], associatedDataLength * 8);
        BinaryPrimitives.WriteUInt64LittleEndian(bb[8..], plaintextLength * 8);

        Vector128<byte> t = _s[3] ^ Vector128.Create(b);

        for (int i = 0; i < 7; i++) {
            Update(t);
        }

        if (tag.Length == 16) {
            Vector128<byte> a = _s[0] ^ _s[1] ^ _s[2] ^ _s[3] ^ _s[4] ^ _s[5];
            a.CopyTo(tag);
        }
        else {
            Vector128<byte> a1 = _s[0] ^ _s[1] ^ _s[2];
            Vector128<byte> a2 = _s[3] ^ _s[4] ^ _s[5];
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
