import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.ChaCha20ParameterSpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.security.SecureRandom;

public class ChaCha20FileEncryptor {

    private static final int NONCE_LENGTH = 12; // Nonce length for ChaCha20 (96 bits)
    private static final int KEY_LENGTH = 256; // Key length in bits

    public static void main(String[] args) throws Exception {
        // User input for nonce
        String email = "user@example.com"; // Replace with user-provided email
        String phoneNumber = "1234567890"; // Replace with user-provided phone number

        // Derive nonce from email and phone number
        byte[] nonce = generateNonceFromUserInput(email, phoneNumber);

        // Input and output file paths
        File inputFile = new File("input.txt"); // Replace with your file path
        String encryptedFileName = "encrypted_" + encodeNonce(nonce) + ".dat";
        File encryptedFile = new File(encryptedFileName);
        File decryptedFile = new File("decrypted.txt");

        // Generate a key
        SecretKey key = generateKey();

        // Encrypt the file
        encryptFile(inputFile, encryptedFile, key, nonce);

        // Decrypt the file
        decryptFile(encryptedFile, decryptedFile, key, nonce);

        System.out.println("Encryption and decryption completed.");
    }

    private static SecretKey generateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("ChaCha20");
        keyGenerator.init(KEY_LENGTH, new SecureRandom());
        return keyGenerator.generateKey();
    }

    private static byte[] generateNonceFromUserInput(String email, String phoneNumber) {
        byte[] nonce = new byte[NONCE_LENGTH];

        // Extract first 4 characters of the email and last 4 digits of the phone number
        String emailPart = email.substring(0, Math.min(4, email.length()));
        String phonePart = phoneNumber.substring(Math.max(0, phoneNumber.length() - 4));

        // Combine parts into a 12-byte nonce
        byte[] emailBytes = emailPart.getBytes();
        byte[] phoneBytes = phonePart.getBytes();

        System.arraycopy(emailBytes, 0, nonce, 0, Math.min(emailBytes.length, 4));
        System.arraycopy(phoneBytes, 0, nonce, 4, Math.min(phoneBytes.length, 4));

        // Fill the rest of the nonce with random bytes
        new SecureRandom().nextBytes(nonce, 8, 4);

        return nonce;
    }

    private static String encodeNonce(byte[] nonce) {
        StringBuilder encoded = new StringBuilder();
        for (byte b : nonce) {
            encoded.append(String.format("%02x", b));
        }
        return encoded.toString();
    }

    private static void encryptFile(File inputFile, File outputFile, SecretKey key, byte[] nonce) throws Exception {
        byte[] inputBytes = Files.readAllBytes(inputFile.toPath());

        // Configure cipher for encryption
        Cipher cipher = Cipher.getInstance("ChaCha20");
        ChaCha20ParameterSpec paramSpec = new ChaCha20ParameterSpec(nonce, 0);
        cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);

        // Encrypt data
        byte[] encryptedBytes = cipher.doFinal(inputBytes);

        // Write encrypted data to the output file
        try (FileOutputStream outputStream = new FileOutputStream(outputFile)) {
            outputStream.write(encryptedBytes);
        }
    }

    private static void decryptFile(File inputFile, File outputFile, SecretKey key, byte[] nonce) throws Exception {
        byte[] encryptedBytes = Files.readAllBytes(inputFile.toPath());

        // Configure cipher for decryption
        Cipher cipher = Cipher.getInstance("ChaCha20");
        ChaCha20ParameterSpec paramSpec = new ChaCha20ParameterSpec(nonce, 0);
        cipher.init(Cipher.DECRYPT_MODE, key, paramSpec);

        // Decrypt data
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        // Write decrypted data to the output file
        try (FileOutputStream outputStream = new FileOutputStream(outputFile)) {
            outputStream.write(decryptedBytes);
        }
    }
}
