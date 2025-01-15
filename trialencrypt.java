import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.ChaCha20ParameterSpec;

public class trialencrypt {

    private static final int NONCE_LENGTH = 12; // Nonce length for ChaCha20 (96 bits)
    private static final int KEY_LENGTH = 256; // Key length in bits

    public static void main(String[] args) throws Exception {
        // Input and output file paths
        File inputFile = new File("input.txt"); // Replace with your file path
        File encryptedFile = new File("encrypted.dat");
        File decryptedFile = new File("decrypted.txt");

        // Generate a key and nonce
        SecretKey key = generateKey();
        byte[] nonce = generateNonce();

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

    private static byte[] generateNonce() {
        byte[] nonce = new byte[NONCE_LENGTH];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    private static void encryptFile(File inputFile, File outputFile, SecretKey key, byte[] nonce) throws Exception {
        byte[] inputBytes = Files.readAllBytes(inputFile.toPath());

        // Configure cipher for encryption
        Cipher cipher = Cipher.getInstance("ChaCha20");
        ChaCha20ParameterSpec paramSpec = new ChaCha20ParameterSpec(nonce, 0);
        cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);

        // Encrypt data
        byte[] encryptedBytes = cipher.doFinal(inputBytes);

        // Write nonce and encrypted data to the output file
        try (FileOutputStream outputStream = new FileOutputStream(outputFile)) {
            outputStream.write(nonce);
            outputStream.write(encryptedBytes);
        }
    }

    private static void decryptFile(File inputFile, File outputFile, SecretKey key, byte[] originalNonce) throws Exception {
        byte[] fileBytes = Files.readAllBytes(inputFile.toPath());

        // Extract nonce and encrypted data
        byte[] nonce = new byte[NONCE_LENGTH];
        System.arraycopy(fileBytes, 0, nonce, 0, NONCE_LENGTH);
        byte[] encryptedBytes = new byte[fileBytes.length - NONCE_LENGTH];
        System.arraycopy(fileBytes, NONCE_LENGTH, encryptedBytes, 0, encryptedBytes.length);

        // Configure cipher for decryption
        Cipher cipher = Cipher.getInstance("ChaCha20");
        ChaCha20ParameterSpec paramSpec = new ChaCha20ParameterSpec(originalNonce, 0);
        cipher.init(Cipher.DECRYPT_MODE, key, paramSpec);

        // Decrypt data
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        // Write decrypted data to the output file
        try (FileOutputStream outputStream = new FileOutputStream(outputFile)) {
            outputStream.write(decryptedBytes);
        }
    }
}
