package com.github.firststraw.jasypt;

import java.math.BigDecimal;
import java.math.BigInteger;
import org.jasypt.encryption.pbe.StandardPBEBigDecimalEncryptor;
import org.jasypt.encryption.pbe.StandardPBEBigIntegerEncryptor;
import org.jasypt.encryption.pbe.StandardPBEByteEncryptor;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.encryption.pbe.config.SimplePBEConfig;
import org.jasypt.salt.StringFixedSaltGenerator;

/**
 * Exposes password-based encryption and decryption of various types using the Jasypt default
 * encryption and hash algorithms.
 */
public class JasyptPBEncryptor {

    private static final String NULL_MESSAGE_ERROR = "Message is null.";
    private static final String EMPTY_MESSAGE_ERROR = "Message is empty.";
    private static final String NULL_ENCRYPTED_MESSAGE_ERROR = "Encrypted message is null.";
    private static final String EMPTY_ENCRYPTED_MESSAGE_ERROR = "Encrypted message is empty.";

    private final StandardPBEBigDecimalEncryptor decimalEncryptor;
    private final StandardPBEBigIntegerEncryptor integerEncryptor;
    private final StandardPBEByteEncryptor byteEncryptor;
    private final StandardPBEStringEncryptor stringEncryptor;

    /**
     * Instantiates the encryptor using the default Jasypt encryption and hash algorithms.
     *
     * @param password encryption password to initialize the encryptor with
     * @param salt encryption salt to initialize the encryptor with
     */
    public JasyptPBEncryptor(final String password, final String salt) {
        if (password == null) {
            throw new NullPointerException("Encryption password is null.");
        } else if (password.isEmpty()) {
            throw new IllegalArgumentException("Encryption password is empty.");
        }

        if (salt == null) {
            throw new NullPointerException("Encryption salt is null.");
        } else if (salt.isEmpty()) {
            throw new IllegalArgumentException("Encryption salt is empty.");
        }

        final SimplePBEConfig config = new SimplePBEConfig();
        config.setPassword(password);
        config.setSaltGenerator(new StringFixedSaltGenerator(salt));

        decimalEncryptor = new StandardPBEBigDecimalEncryptor();
        decimalEncryptor.setConfig(config);

        integerEncryptor = new StandardPBEBigIntegerEncryptor();
        integerEncryptor.setConfig(config);

        byteEncryptor = new StandardPBEByteEncryptor();
        byteEncryptor.setConfig(config);

        stringEncryptor = new StandardPBEStringEncryptor();
        stringEncryptor.setConfig(config);
    }

    /**
     * Encrypts the specified {@link BigDecimal}.
     *
     * @param message {@link BigDecimal} to encrypt
     * @return the encrypted {@link BigDecimal}
     */
    public BigDecimal encrypt(final BigDecimal message) {
        if (message == null) {
            throw new NullPointerException(NULL_MESSAGE_ERROR);
        }

        return decimalEncryptor.encrypt(message);
    }

    /**
     * Encrypts the specified {@link BigInteger}.
     *
     * @param message {@link BigInteger} to encrypt
     * @return the encrypted {@link BigInteger}
     */
    public BigInteger encrypt(final BigInteger message) {
        if (message == null) {
            throw new NullPointerException(NULL_MESSAGE_ERROR);
        }

        return integerEncryptor.encrypt(message);
    }

    /**
     * Encrypts the specified {@link byte}s.
     *
     * @param message {@link byte}s to encrypt
     * @return the encrypted {@link byte}s
     */
    public byte[] encrypt(final byte[] message) {
        if (message == null) {
            throw new NullPointerException(NULL_MESSAGE_ERROR);
        } else if (message.length == 0) {
            throw new IllegalArgumentException(EMPTY_MESSAGE_ERROR);
        }

        return byteEncryptor.encrypt(message);
    }

    /**
     * Encrypts the specified {@link String}.
     *
     * @param message {@link String} to encrypt
     * @return the encrypted {@link String}
     */
    public String encrypt(final String message) {
        if (message == null) {
            throw new NullPointerException(NULL_MESSAGE_ERROR);
        } else if (message.isEmpty()) {
            throw new IllegalArgumentException(EMPTY_MESSAGE_ERROR);
        }

        return stringEncryptor.encrypt(message);
    }

    /**
     * Decrypts the specified encrypted {@link BigDecimal}.
     *
     * @param encryptedMessage encrypted {@link BigDecimal} to decrypt
     * @return the decrypted {@link BigDecimal}
     */
    public BigDecimal decrypt(final BigDecimal encryptedMessage) {
        if (encryptedMessage == null) {
            throw new NullPointerException(NULL_ENCRYPTED_MESSAGE_ERROR);
        }

        return decimalEncryptor.decrypt(encryptedMessage);
    }

    /**
     * Decrypts the specified encrypted {@link BigInteger}.
     *
     * @param encryptedMessage encrypted {@link BigInteger} to decrypt
     * @return the decrypted {@link BigInteger}
     */
    public BigInteger decrypt(final BigInteger encryptedMessage) {
        if (encryptedMessage == null) {
            throw new NullPointerException(NULL_ENCRYPTED_MESSAGE_ERROR);
        }

        return integerEncryptor.decrypt(encryptedMessage);
    }

    /**
     * Decrypts the specified encrypted {@link byte}s.
     *
     * @param encryptedMessage encrypted {@link byte}s to decrypt
     * @return the decrypted {@link byte}s
     */
    public byte[] decrypt(final byte[] encryptedMessage) {
        if (encryptedMessage == null) {
            throw new NullPointerException(NULL_ENCRYPTED_MESSAGE_ERROR);
        } else if (encryptedMessage.length == 0) {
            throw new IllegalArgumentException(EMPTY_ENCRYPTED_MESSAGE_ERROR);
        }

        return byteEncryptor.decrypt(encryptedMessage);
    }

    /**
     * Decrypts the specified encrypted {@link String}.
     *
     * @param encryptedMessage encrypted {@link String} to decrypt
     * @return the decrypted {@link String}
     */
    public String decrypt(final String encryptedMessage) {
        if (encryptedMessage == null) {
            throw new NullPointerException(NULL_ENCRYPTED_MESSAGE_ERROR);
        } else if (encryptedMessage.isEmpty()) {
            throw new IllegalArgumentException(EMPTY_ENCRYPTED_MESSAGE_ERROR);
        }

        return stringEncryptor.decrypt(encryptedMessage);
    }

}
