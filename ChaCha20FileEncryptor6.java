import java.io.*;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.*;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.IvParameterSpec;

public class ChaCha20FileEncryptor6 {

    private static final int NONCE_LENGTH = 12; // 1Nonce length for ChaCha20 (96 bits)
    private static final int IV_LENGTH = 16; // IV length for AES-CTR (128 bits)
    private static final int KEY_LENGTH = 256; // Key length in bits

    public static void main(String[] args) throws Exception {
        // User input for nonce
        String email = "user@example.com"; // Replace with user-provided email
        String phoneNumber = "1234567890"; // Replace with user-provided phone number

        // Derive nonce from email and phone number
        byte[] nonce = generateNonceFromUserInput(email, phoneNumber);

        // Input and output file paths
        File inputFile = new File("inputimg.webp"); // Replace with your file path
        String doubleEncryptedFileName = "double_encrypted_aesctr_" + encodeNonce(nonce) + ".dat";
        File doubleEncryptedFile = new File(doubleEncryptedFileName);
        File decryptedFile = new File("decrypted.webp");

        // Generate keys
        SecretKey chachaKey = generateKey();
        SecretKey aesKey = generateAESKey();
        byte[] iv = generateIV();

        // Encrypt the file with ChaCha20 and then AES-CTR
        File chachaEncryptedFile = encryptFileWithPadding(inputFile, chachaKey, nonce);
        encryptFileAESCTR(chachaEncryptedFile, doubleEncryptedFile, aesKey, iv);

        // Log entropy for the double-encrypted file
        logEntropy(doubleEncryptedFile);

        // Decrypt the AES-CTR-encrypted file directly to the final decrypted output
        decryptFileAESCTRToFinal(doubleEncryptedFile, decryptedFile, aesKey, chachaKey, nonce, iv);

        System.out.println("Double encryption and decryption completed.");
    }

    private static SecretKey generateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("ChaCha20");
        keyGenerator.init(KEY_LENGTH, new SecureRandom());
        return keyGenerator.generateKey();
    }

    private static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
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

        // Generate random bytes for the remaining part of the nonce
        byte[] randomBytes = new byte[4]; // Remaining 4 bytes
        new SecureRandom().nextBytes(randomBytes);
        System.arraycopy(randomBytes, 0, nonce, 8, 4);

        return nonce;
    }

    private static byte[] generateIV() {
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    private static String encodeNonce(byte[] nonce) {
        StringBuilder encoded = new StringBuilder();
        for (byte b : nonce) {
            encoded.append(String.format("%02x", b));
        }
        return encoded.toString();
    }

    private static File encryptFileWithPadding(File inputFile, SecretKey key, byte[] nonce) throws Exception {
        byte[] inputBytes = Files.readAllBytes(inputFile.toPath());

        // Add random padding to increase entropy for small files
        SecureRandom random = new SecureRandom();
        int paddingLength = Math.max(16, 256 - inputBytes.length); // Ensure minimum padding
        byte[] padding = new byte[paddingLength];
        random.nextBytes(padding);

        byte[] paddedInput = new byte[inputBytes.length + paddingLength];
        System.arraycopy(inputBytes, 0, paddedInput, 0, inputBytes.length);
        System.arraycopy(padding, 0, paddedInput, inputBytes.length, paddingLength);

        // Configure cipher for encryption
        Cipher cipher = Cipher.getInstance("ChaCha20");
        ChaCha20ParameterSpec paramSpec = new ChaCha20ParameterSpec(nonce, 0);
        cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);

        // Encrypt data
        byte[] encryptedBytes = cipher.doFinal(paddedInput);

        File outputFile = new File("temp_chacha_encrypted.dat");
        try (FileOutputStream outputStream = new FileOutputStream(outputFile)) {
            // Write the original content length first (4 bytes)
            outputStream.write(intToByteArray(inputBytes.length));
            // Write encrypted data
            outputStream.write(encryptedBytes);
        }

        return outputFile;
    }

    private static void encryptFileAESCTR(File inputFile, File outputFile, SecretKey key, byte[] iv) throws Exception {
        byte[] inputBytes = Files.readAllBytes(inputFile.toPath());

        // Configure cipher for AES-CTR encryption
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

        // Encrypt data
        byte[] encryptedBytes = cipher.doFinal(inputBytes);

        // Write encrypted data to the output file
        try (FileOutputStream outputStream = new FileOutputStream(outputFile)) {
            outputStream.write(encryptedBytes);
        }

        // Delete the intermediate file
        inputFile.delete();
    }

    private static void decryptFileAESCTRToFinal(File inputFile, File outputFile, SecretKey aesKey, SecretKey chachaKey, byte[] nonce, byte[] iv) throws Exception {
        try (FileInputStream inputStream = new FileInputStream(inputFile);
             FileOutputStream outputStream = new FileOutputStream(outputFile)) {

            // Configure cipher for AES-CTR decryption
            Cipher aesCipher = Cipher.getInstance("AES/CTR/NoPadding");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            aesCipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);

            byte[] buffer = new byte[8192]; // 8 KB buffer
            int bytesRead;

            // Decrypt AES-CTR layer in chunks
            ByteArrayOutputStream decryptedStream = new ByteArrayOutputStream();

            while ((bytesRead = inputStream.read(buffer)) != -1) {
                byte[] decryptedChunk = aesCipher.update(buffer, 0, bytesRead);
                decryptedStream.write(decryptedChunk);
            }

            byte[] finalDecryptedBytes = aesCipher.doFinal();
            decryptedStream.write(finalDecryptedBytes);

            byte[] decryptedAESBytes = decryptedStream.toByteArray();

            // Extract original content length (first 4 bytes)
            int originalLength = byteArrayToInt(decryptedAESBytes, 0);
            byte[] encryptedChaChaBytes = new byte[decryptedAESBytes.length - 4];
            System.arraycopy(decryptedAESBytes, 4, encryptedChaChaBytes, 0, encryptedChaChaBytes.length);

            // Configure cipher for ChaCha20 decryption
            Cipher chachaCipher = Cipher.getInstance("ChaCha20");
            ChaCha20ParameterSpec chachaParamSpec = new ChaCha20ParameterSpec(nonce, 0);
            chachaCipher.init(Cipher.DECRYPT_MODE, chachaKey, chachaParamSpec);

            // Decrypt ChaCha20 layer in chunks
            ByteArrayOutputStream finalDecryptedStream = new ByteArrayOutputStream();
            int chunkSize = 8192; // Adjust chunk size as needed
            int encryptedBytesOffset = 0;

            while (encryptedBytesOffset < encryptedChaChaBytes.length) {
                int chunkLength = Math.min(chunkSize, encryptedChaChaBytes.length - encryptedBytesOffset);
                byte[] encryptedChunk = new byte[chunkLength];
                System.arraycopy(encryptedChaChaBytes, encryptedBytesOffset, encryptedChunk, 0, chunkLength);

                byte[] decryptedChaChaChunk = chachaCipher.update(encryptedChunk);
                finalDecryptedStream.write(decryptedChaChaChunk);
                encryptedBytesOffset += chunkLength;
            }

            byte[] finalDecryptedChaChaBytes = chachaCipher.doFinal();
            finalDecryptedStream.write(finalDecryptedChaChaBytes);

            byte[] decryptedData = finalDecryptedStream.toByteArray();

            // Extract the original content
            byte[] originalBytes = new byte[originalLength];
            System.arraycopy(decryptedData, 0, originalBytes, 0, originalLength);

            // Write the original data to the output file
            outputStream.write(originalBytes);
        }
    }

    private static byte[] intToByteArray(int value) {
        return new byte[] {
            (byte) (value >> 24),
            (byte) (value >> 16),
            (byte) (value >> 8),
            (byte) value
        };
    }

    private static int byteArrayToInt(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xFF) << 24) |
               ((bytes[offset + 1] & 0xFF) << 16) |
               ((bytes[offset + 2] & 0xFF) << 8) |
               (bytes[offset + 3] & 0xFF);
    }

    private static void logEntropy(File file) throws Exception {
        byte[] fileBytes = Files.readAllBytes(file.toPath());
        double entropy = calculateEntropy(fileBytes);
        System.out.printf("Entropy of file '%s': %.2f bits/byte%n", file.getName(), entropy);
    }

    private static double calculateEntropy(byte[] data) {
        Map<Byte, Integer> frequencyMap = new HashMap<>();
        for (byte b : data) {
            frequencyMap.put(b, frequencyMap.getOrDefault(b, 0) + 1);
        }

        double entropy = 0.0;
        int dataLength = data.length;

        for (int count : frequencyMap.values()) {
            double probability = (double) count / dataLength;
            entropy -= probability * (Math.log(probability) / Math.log(2));
        }

        return entropy;
    }
}
