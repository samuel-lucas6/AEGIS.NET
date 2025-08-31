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
            using var aegis128L = new AEGIS128Lx86(key, nonce);
            aegis128L.Encrypt(ciphertext, plaintext, associatedData, tagSize);
        }
        else if (AEGIS128LArm.IsSupported()) {
            using var aegis128L = new AEGIS128LArm(key, nonce);
            aegis128L.Encrypt(ciphertext, plaintext, associatedData, tagSize);
        }
        else {
            using var aegis128L = new AEGIS128LSoft(key, nonce);
            aegis128L.Encrypt(ciphertext, plaintext, associatedData, tagSize);
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
            using var aegis128L = new AEGIS128Lx86(key, nonce);
            aegis128L.Decrypt(plaintext, ciphertext, associatedData, tagSize);
        }
        else if (AEGIS128LArm.IsSupported()) {
            using var aegis128L = new AEGIS128LArm(key, nonce);
            aegis128L.Decrypt(plaintext, ciphertext, associatedData, tagSize);
        }
        else {
            using var aegis128L = new AEGIS128LSoft(key, nonce);
            aegis128L.Decrypt(plaintext, ciphertext, associatedData, tagSize);
        }
    }
}
