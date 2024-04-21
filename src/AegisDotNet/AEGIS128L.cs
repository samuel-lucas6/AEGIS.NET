namespace AegisDotNet;

public static class AEGIS128L
{
    public const int KeySize = 16;
    public const int NonceSize = 16;
    public const int MinTagSize = 16;
    public const int MaxTagSize = 32;

    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default, int tagSize = MinTagSize)
    {
        if (tagSize != MinTagSize && tagSize != MaxTagSize) { throw new ArgumentOutOfRangeException(nameof(tagSize), tagSize, $"{nameof(tagSize)} must be equal to {MinTagSize} or {MaxTagSize}."); }
        if (ciphertext.Length != plaintext.Length + tagSize) { throw new ArgumentOutOfRangeException(nameof(ciphertext), ciphertext.Length, $"{nameof(ciphertext)} must be {plaintext.Length + tagSize} bytes long."); }
        if (nonce.Length != NonceSize) { throw new ArgumentOutOfRangeException(nameof(nonce), nonce.Length, $"{nameof(nonce)} must be {NonceSize} bytes long."); }
        if (key.Length != KeySize) { throw new ArgumentOutOfRangeException(nameof(key), key.Length, $"{nameof(key)} must be {KeySize} bytes long."); }

        if (AEGIS128Lx86.IsSupported()) {
            AEGIS128Lx86.Encrypt(ciphertext, plaintext, nonce, key, associatedData, tagSize);
        }
        else if (AEGIS128LArm.IsSupported()) {
            AEGIS128LArm.Encrypt(ciphertext, plaintext, nonce, key, associatedData, tagSize);
        }
        else {
            AEGIS128LSoft.Encrypt(ciphertext, plaintext, nonce, key, associatedData, tagSize);
        }
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default, int tagSize = MinTagSize)
    {
        if (tagSize != MinTagSize && tagSize != MaxTagSize) { throw new ArgumentOutOfRangeException(nameof(tagSize), tagSize, $"{nameof(tagSize)} must be equal to {MinTagSize} or {MaxTagSize}."); }
        if (ciphertext.Length < tagSize) { throw new ArgumentOutOfRangeException(nameof(ciphertext), ciphertext.Length, $"{nameof(ciphertext)} must be at least {tagSize} bytes long."); }
        if (plaintext.Length != ciphertext.Length - tagSize) { throw new ArgumentOutOfRangeException(nameof(plaintext), plaintext.Length, $"{nameof(plaintext)} must be {ciphertext.Length - tagSize} bytes long."); }
        if (nonce.Length != NonceSize) { throw new ArgumentOutOfRangeException(nameof(nonce), nonce.Length, $"{nameof(nonce)} must be {NonceSize} bytes long."); }
        if (key.Length != KeySize) { throw new ArgumentOutOfRangeException(nameof(key), key.Length, $"{nameof(key)} must be {KeySize} bytes long."); }

        if (AEGIS128Lx86.IsSupported()) {
            AEGIS128Lx86.Decrypt(plaintext, ciphertext, nonce, key, associatedData, tagSize);
        }
        else if (AEGIS128LArm.IsSupported()) {
            AEGIS128LArm.Decrypt(plaintext, ciphertext, nonce, key, associatedData, tagSize);
        }
        else {
            AEGIS128LSoft.Decrypt(plaintext, ciphertext, nonce, key, associatedData, tagSize);
        }
    }
}
