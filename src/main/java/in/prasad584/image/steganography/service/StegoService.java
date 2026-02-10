package in.prasad584.image.steganography.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

@Service
public class StegoService {

    // Header format: MAGIC(5) + VERSION(1) + SALT(16) + IV(12) + EXPLICIT_PASSWORD + CIPHER_LEN(4) + CIPHERTEXT(...)
    @Value("${app.stego.key}")
    private String EXPLICIT_PASSWORD;
    private static final byte[] MAGIC = "STEGO1".getBytes(StandardCharsets.UTF_8);
    private static final byte VERSION = 1;
    private static final int SALT_LEN = 16;
    private static final int IV_LEN = 12;
    private static final int ITERATIONS = 100_000;
    private static final int KEY_LENGTH = 256;
    private boolean EXPLICIT_PASSWORD_NEEDED;


    public byte[] embedMessage(byte[] bytes, String message, String password) throws Exception {
        BufferedImage image = ImageIO.read(new ByteArrayInputStream(bytes));
        if (image == null) throw new Exception("Image is null");

        EXPLICIT_PASSWORD_NEEDED = password == null;
        byte[] salt = secureRandom(SALT_LEN);
        byte[] iv = secureRandom(IV_LEN);

        assert (EXPLICIT_PASSWORD_NEEDED ? EXPLICIT_PASSWORD : password) != null;
        SecretKey key = deriveKey((EXPLICIT_PASSWORD_NEEDED ? EXPLICIT_PASSWORD : password).toCharArray(), salt);


        byte[] plaintext = message.getBytes(StandardCharsets.UTF_8);
        byte[] cipher = encryptAesGcm(key, iv, plaintext);

        byte[] header = buildHeader(salt, iv, EXPLICIT_PASSWORD_NEEDED ? 1 : 0 , cipher.length);
        byte[] payload = concat(header, cipher);

        long capacityBits = (long) image.getWidth() * image.getHeight() * 3;
        long requiredBits = (long) payload.length * 8L;
        if (requiredBits > capacityBits) {
            throw new IllegalArgumentException("Image too small. Need " +
                    ((requiredBits + 7) / 8) + " bytes capacity, have ~" + (capacityBits / 8) + " bytes.");
        }

        writePayloadToImageLSB(image, payload);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ImageIO.write(image, "png", out);
        return out.toByteArray();
    }

    public String extractMessage(byte[] stego, String password) throws Exception {
        BufferedImage image = ImageIO.read(new ByteArrayInputStream(stego));
        if (image == null) return null;

        int headerBits = (MAGIC.length + 1 + SALT_LEN + IV_LEN + 1 + 4) * 8;
        byte[] header = readBits(image, headerBits);


        int offset = 0;
        byte[] magicRead = new byte[MAGIC.length];
        System.arraycopy(header, offset, magicRead, 0, MAGIC.length);
        offset += MAGIC.length;

        if (!java.util.Arrays.equals(magicRead, MAGIC)) {
            throw new IllegalArgumentException("Invalid stego image (bad magic).");
        }

        byte versionRead = header[offset++];
        if (versionRead != VERSION) {
            throw new IllegalArgumentException("Unsupported version: " + versionRead);
        }

        byte[] salt = new byte[SALT_LEN];
        System.arraycopy(header, offset, salt, 0, SALT_LEN);
        offset += SALT_LEN;

        byte[] iv = new byte[IV_LEN];
        System.arraycopy(header, offset, iv, 0, IV_LEN);
        offset += IV_LEN;

        EXPLICIT_PASSWORD_NEEDED = header[offset++] == 1;

        int cipherLen = ((header[offset] & 0xFF) << 24) |
                ((header[offset + 1] & 0xFF) << 16) |
                ((header[offset + 2] & 0xFF) << 8) |
                (header[offset + 3] & 0xFF);


        byte[] fullPayload = readBits(image, (header.length + cipherLen) * 8);
        byte[] cipherBytes = Arrays.copyOfRange(fullPayload, header.length, header.length + cipherLen);

        SecretKey key = deriveKey((EXPLICIT_PASSWORD_NEEDED ? EXPLICIT_PASSWORD : password).toCharArray(), salt);
        byte[] plaintext = decryptAesGcm(key, iv, cipherBytes);

        return new String(plaintext, StandardCharsets.UTF_8);
    }

    private void writePayloadToImageLSB(BufferedImage image, byte[] payload) {
        int width = image.getWidth();
        int height = image.getHeight();

        int bitIndex = 0;
        for (int y = 0; y < height && bitIndex < payload.length * 8; y++) {
            for (int x = 0; x < width && bitIndex < payload.length * 8; x++) {
                int rgb = image.getRGB(x, y);

                int r = (rgb >> 16) & 0xFF;
                int g = (rgb >> 8) & 0xFF;
                int b = rgb & 0xFF;


                for (int channel = 0; channel < 3 && bitIndex < payload.length * 8; channel++) {
                    int bit = (payload[bitIndex / 8] >> (7 - (bitIndex % 8))) & 1;
                    if (channel == 0) {
                        r = (r & 0xFE) | bit;
                    } else if (channel == 1) {
                        g = (g & 0xFE) | bit;
                    } else {
                        b = (b & 0xFE) | bit;
                    }
                    bitIndex++;
                }

                int newRgb = (0xFF << 24) | (r << 16) | (g << 8) | b;
                image.setRGB(x, y, newRgb);
            }
        }
    }

    private byte[] readBits(BufferedImage image, int numBits) {
        int width = image.getWidth();
        int height = image.getHeight();
        byte[] out = new byte[(numBits + 7) / 8];

        int bitIndex = 0;
        for (int y = 0; y < height && bitIndex < numBits; y++) {
            for (int x = 0; x < width && bitIndex < numBits; x++) {
                int rgb = image.getRGB(x, y);

                int r = (rgb >> 16) & 0xFF;
                int g = (rgb >> 8) & 0xFF;
                int b = rgb & 0xFF;

                int[] channels = {r, g, b};
                for (int channel = 0; channel < 3 && bitIndex < numBits; channel++) {
                    int bit = channels[channel] & 1;
                    out[bitIndex / 8] = (byte) ((out[bitIndex / 8] << 1) | bit);
                    bitIndex++;
                }
            }
        }

        int extra = (8 - (numBits % 8)) % 8;
        if (extra > 0) {
            out[out.length - 1] = (byte) (out[out.length - 1] >> extra);
        }

        return out;
    }

    private static byte[] concat(byte[] a, byte[] b) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream(a.length + b.length);
        bos.write(a);
        bos.write(b);
        return bos.toByteArray();
    }

    private byte[] buildHeader(byte[] salt, byte[] iv, int explicit_password, int cipherLen) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bos.write(MAGIC);
        bos.write(VERSION);
        bos.write(salt);
        bos.write(iv);
        bos.write(explicit_password);
        bos.write(new byte[]{
                (byte) ((cipherLen >>> 24) & 0xFF),
                (byte) ((cipherLen >>> 16) & 0xFF),
                (byte) ((cipherLen >>> 8) & 0xFF),
                (byte) ((cipherLen) & 0xFF)
        });
        return bos.toByteArray();
    }

    private static byte[] secureRandom(int len) {
        byte[] out = new byte[len];
        new SecureRandom().nextBytes(out);
        return out;
    }

    private SecretKey deriveKey(char[] password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_LENGTH);
        SecretKey tmp = skf.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), "AES");
    }

    private byte[] encryptAesGcm(SecretKey key, byte[] iv, byte[] data) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
        return cipher.doFinal(data);
    }

    private byte[] decryptAesGcm(SecretKey key, byte[] iv, byte[] data) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcm = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, gcm);
        return cipher.doFinal(data);
    }
}
