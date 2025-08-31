namespace AegisDotNet;

public static class AEGIS256
{
    public const int KeySize = 32;
    public const int NonceSize = 32;
    public const int MinTagSize = 16;
    public const int MaxTagSize = 32;

    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default, int tagSize = MinTagSize)
    {
        if (tagSize != MinTagSize && tagSize != MaxTagSize) { throw new ArgumentOutOfRangeException(nameof(tagSize), tagSize, $"{nameof(tagSize)} must be equal to {MinTagSize} or {MaxTagSize}."); }
        if (ciphertext.Length != plaintext.Length + tagSize) { throw new ArgumentOutOfRangeException(nameof(ciphertext), ciphertext.Length, $"{nameof(ciphertext)} must be {plaintext.Length + tagSize} bytes long."); }
        if (nonce.Length != NonceSize) { throw new ArgumentOutOfRangeException(nameof(nonce), nonce.Length, $"{nameof(nonce)} must be {NonceSize} bytes long."); }
        if (key.Length != KeySize) { throw new ArgumentOutOfRangeException(nameof(key), key.Length, $"{nameof(key)} must be {KeySize} bytes long."); }

        if (AEGIS256x86.IsSupported()) {
            using var aegis256 = new AEGIS256x86(key, nonce);
            aegis256.Encrypt(ciphertext, plaintext, associatedData, tagSize);
        }
        else if (AEGIS256Arm.IsSupported()) {
            using var aegis256 = new AEGIS256Arm(key, nonce);
            aegis256.Encrypt(ciphertext, plaintext, associatedData, tagSize);
        }
        else {
            using var aegis256 = new AEGIS256Soft(key, nonce);
            aegis256.Encrypt(ciphertext, plaintext, associatedData, tagSize);
        }
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default, int tagSize = MinTagSize)
    {
        if (tagSize != MinTagSize && tagSize != MaxTagSize) { throw new ArgumentOutOfRangeException(nameof(tagSize), tagSize, $"{nameof(tagSize)} must be equal to {MinTagSize} or {MaxTagSize}."); }
        if (ciphertext.Length < tagSize) { throw new ArgumentOutOfRangeException(nameof(ciphertext), ciphertext.Length, $"{nameof(ciphertext)} must be at least {tagSize} bytes long."); }
        if (plaintext.Length != ciphertext.Length - tagSize) { throw new ArgumentOutOfRangeException(nameof(plaintext), plaintext.Length, $"{nameof(plaintext)} must be {ciphertext.Length - tagSize} bytes long."); }
        if (nonce.Length != NonceSize) { throw new ArgumentOutOfRangeException(nameof(nonce), nonce.Length, $"{nameof(nonce)} must be {NonceSize} bytes long."); }
        if (key.Length != KeySize) { throw new ArgumentOutOfRangeException(nameof(key), key.Length, $"{nameof(key)} must be {KeySize} bytes long."); }

        if (AEGIS256x86.IsSupported()) {
            using var aegis256 = new AEGIS256x86(key, nonce);
            aegis256.Decrypt(plaintext, ciphertext, associatedData, tagSize);
        }
        else if (AEGIS256Arm.IsSupported()) {
            using var aegis256 = new AEGIS256Arm(key, nonce);
            aegis256.Decrypt(plaintext, ciphertext, associatedData, tagSize);
        }
        else {
            using var aegis256 = new AEGIS256Soft(key, nonce);
            aegis256.Decrypt(plaintext, ciphertext, associatedData, tagSize);
        }
    }
}
