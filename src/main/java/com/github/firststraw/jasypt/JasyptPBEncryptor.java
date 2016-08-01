package com.github.firststraw.jasypt;

import java.math.BigDecimal;
import java.math.BigInteger;
import javax.inject.Inject;
import org.apache.commons.lang3.Validate;
import org.jasypt.encryption.pbe.PBEBigDecimalEncryptor;
import org.jasypt.encryption.pbe.PBEBigIntegerEncryptor;
import org.jasypt.encryption.pbe.PBEByteEncryptor;
import org.jasypt.encryption.pbe.PBEStringEncryptor;
import org.jasypt.encryption.pbe.PooledPBEBigDecimalEncryptor;
import org.jasypt.encryption.pbe.PooledPBEBigIntegerEncryptor;
import org.jasypt.encryption.pbe.PooledPBEByteEncryptor;
import org.jasypt.encryption.pbe.PooledPBEStringEncryptor;
import org.jasypt.encryption.pbe.StandardPBEBigDecimalEncryptor;
import org.jasypt.encryption.pbe.StandardPBEBigIntegerEncryptor;
import org.jasypt.encryption.pbe.StandardPBEByteEncryptor;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.encryption.pbe.config.PBECleanablePasswordConfig;
import org.jasypt.encryption.pbe.config.PBEConfig;

/**
 * Provides a single entry point for encryption and decryption of various types.
 */
public class JasyptPBEncryptor {

    private static final String NULL_MESSAGE_ERROR = "Message is null.";
    private static final String EMPTY_MESSAGE_ERROR = "Message is empty.";
    private static final String NULL_OR_BLANK_MESSAGE_ERROR = "Message is null or blank.";
    private static final String NULL_ENCRYPTED_MESSAGE_ERROR = "Encrypted message is null.";
    private static final String EMPTY_ENCRYPTED_MESSAGE_ERROR = "Encrypted message is empty.";
    private static final String NULL_OR_BLANK_ENCRYPTED_MESSAGE_ERROR =
            "Encrypted message is null or blank.";

    private final PBEBigDecimalEncryptor decimalEncryptor;
    private final PBEBigIntegerEncryptor integerEncryptor;
    private final PBEByteEncryptor byteEncryptor;
    private final PBEStringEncryptor stringEncryptor;

    /**
     * Initializes password-based encryptors for various types using the information in the
     * specified configuration.
     *
     * @param config the configuration to use for initializing the encryptors. If the pool size is
     * {@code null} or 1, then "standard" encryptors will be used. If the pool size is greater than
     * 1, then "pooled" encryptors will be used. If the configuration is an instance of
     * {@link PBECleanablePasswordConfig} then the password will be cleaned after it is copied.
     * @throws NullPointerException if no configuration is specified
     * @throws IllegalArgumentException if the configuration has a pool size that is less than 1
     */
    @Inject
    public JasyptPBEncryptor(final PBEConfig config) {
        Validate.notNull(config, "Encryptor configuration is null.");

        /*
         * Copy the password and set it explicitly on each encryptor rather than letting the
         * encryptors retrieve it from the configuration. If the configuration is a "cleanable
         * password" variant, then its password would be wiped out after the first time one of the
         * encryptors encrypts or decrypts something. Subsequent encryption or decryption by the
         * other encryptors would cause them to attempt initialization from a configuration that no
         * longer has a password.
         */
        final String password = config.getPassword();

        // To improve security, clean the password from the configuration as soon as possible
        if (config instanceof PBECleanablePasswordConfig) {
            ((PBECleanablePasswordConfig) config).cleanPassword();
        }

        if (shouldUsePooled(config.getPoolSize())) {
            final PooledPBEBigDecimalEncryptor pooledDecimalEncryptor =
                    new PooledPBEBigDecimalEncryptor();
            pooledDecimalEncryptor.setConfig(config);
            pooledDecimalEncryptor.setPassword(password);
            decimalEncryptor = pooledDecimalEncryptor;

            final PooledPBEBigIntegerEncryptor pooledIntegerEncryptor =
                    new PooledPBEBigIntegerEncryptor();
            pooledIntegerEncryptor.setConfig(config);
            pooledIntegerEncryptor.setPassword(password);
            integerEncryptor = pooledIntegerEncryptor;

            final PooledPBEByteEncryptor pooledByteEncryptor = new PooledPBEByteEncryptor();
            pooledByteEncryptor.setConfig(config);
            pooledByteEncryptor.setPassword(password);
            byteEncryptor = pooledByteEncryptor;

            final PooledPBEStringEncryptor pooledStringEncryptor = new PooledPBEStringEncryptor();
            pooledStringEncryptor.setConfig(config);
            pooledStringEncryptor.setPassword(password);
            stringEncryptor = pooledStringEncryptor;
        } else {
            final StandardPBEBigDecimalEncryptor stdDecimalEncryptor =
                    new StandardPBEBigDecimalEncryptor();
            stdDecimalEncryptor.setConfig(config);
            stdDecimalEncryptor.setPassword(password);
            decimalEncryptor = stdDecimalEncryptor;

            final StandardPBEBigIntegerEncryptor stdIntegerEncryptor =
                    new StandardPBEBigIntegerEncryptor();
            stdIntegerEncryptor.setConfig(config);
            stdIntegerEncryptor.setPassword(password);
            integerEncryptor = stdIntegerEncryptor;

            final StandardPBEByteEncryptor stdByteEncryptor = new StandardPBEByteEncryptor();
            stdByteEncryptor.setConfig(config);
            stdByteEncryptor.setPassword(password);
            byteEncryptor = stdByteEncryptor;

            final StandardPBEStringEncryptor stdStringEncryptor = new StandardPBEStringEncryptor();
            stdStringEncryptor.setConfig(config);
            stdStringEncryptor.setPassword(password);
            stringEncryptor = stdStringEncryptor;
        }
    }

    /**
     * Checks the configurations pool size to determine whether to use pooled encryptors. Pooled
     * encryptors are used when the pool size is greater than 1.
     *
     * @param config the configuration containing the pool size
     * @return {@code true} if pooled encryptors should be used, otherwise {@code false}
     * @throws IllegalArgumentException if the pool size is invalid (less than 1)
     */
    private boolean shouldUsePooled(final Integer poolSize) {
        if (poolSize == null || poolSize == 1) {
            return false;
        } else if (poolSize < 1) {
            throw new IllegalArgumentException("Pool size must be null or greater than zero.");
        } else {
            return true;
        }
    }

    /**
     * Encrypts the specified {@link BigDecimal}.
     *
     * @param message {@link BigDecimal} to encrypt
     * @return the encrypted {@link BigDecimal}
     * @throws NullPointerException if the message is {@code null}
     */
    public BigDecimal encrypt(final BigDecimal message) {
        Validate.notNull(message, NULL_MESSAGE_ERROR);

        return decimalEncryptor.encrypt(message);
    }

    /**
     * Encrypts the specified {@link BigInteger}.
     *
     * @param message {@link BigInteger} to encrypt
     * @return the encrypted {@link BigInteger}
     * @throws NullPointerException if the message is {@code null}
     */
    public BigInteger encrypt(final BigInteger message) {
        Validate.notNull(message, NULL_MESSAGE_ERROR);

        return integerEncryptor.encrypt(message);
    }

    /**
     * Encrypts the specified {@link byte}s.
     *
     * @param message {@link byte}s to encrypt
     * @return the encrypted {@link byte}s
     * @throws NullPointerException if the message is {@code null}
     * @throws IllegalArgumentException if the message is empty
     */
    public byte[] encrypt(final byte[] message) {
        Validate.notNull(message, NULL_MESSAGE_ERROR);
        Validate.isTrue(message.length > 0, EMPTY_MESSAGE_ERROR);

        return byteEncryptor.encrypt(message);
    }

    /**
     * Encrypts the specified {@link String}.
     *
     * @param message {@link String} to encrypt
     * @return the encrypted {@link String}
     * @throws NullPointerException if the message is {@code null}
     * @throws IllegalArgumentException if the message is empty
     */
    public String encrypt(final String message) {
        Validate.notBlank(message, NULL_OR_BLANK_MESSAGE_ERROR);

        return stringEncryptor.encrypt(message);
    }

    /**
     * Decrypts the specified encrypted {@link BigDecimal}.
     *
     * @param encryptedMessage encrypted {@link BigDecimal} to decrypt
     * @return the decrypted {@link BigDecimal}
     * @throws NullPointerException if the encrypted message is null
     */
    public BigDecimal decrypt(final BigDecimal encryptedMessage) {
        Validate.notNull(encryptedMessage, NULL_ENCRYPTED_MESSAGE_ERROR);

        return decimalEncryptor.decrypt(encryptedMessage);
    }

    /**
     * Decrypts the specified encrypted {@link BigInteger}.
     *
     * @param encryptedMessage encrypted {@link BigInteger} to decrypt
     * @return the decrypted {@link BigInteger}
     * @throws NullPointerException if the encrypted message is null
     */
    public BigInteger decrypt(final BigInteger encryptedMessage) {
        Validate.notNull(encryptedMessage, NULL_ENCRYPTED_MESSAGE_ERROR);

        return integerEncryptor.decrypt(encryptedMessage);
    }

    /**
     * Decrypts the specified encrypted {@link byte}s.
     *
     * @param encryptedMessage encrypted {@link byte}s to decrypt
     * @return the decrypted {@link byte}s
     * @throws NullPointerException if the encrypted message is null
     * @throws IllegalArgumentException if the encrypted message is empty
     */
    public byte[] decrypt(final byte[] encryptedMessage) {
        Validate.notNull(encryptedMessage, NULL_ENCRYPTED_MESSAGE_ERROR);
        Validate.isTrue(encryptedMessage.length > 0, EMPTY_ENCRYPTED_MESSAGE_ERROR);

        return byteEncryptor.decrypt(encryptedMessage);
    }

    /**
     * Decrypts the specified encrypted {@link String}.
     *
     * @param encryptedMessage encrypted {@link String} to decrypt
     * @return the decrypted {@link String}
     * @throws NullPointerException if the encrypted message is null
     * @throws IllegalArgumentException if the encrypted message is empty
     */
    public String decrypt(final String encryptedMessage) {
        Validate.notBlank(encryptedMessage, NULL_OR_BLANK_ENCRYPTED_MESSAGE_ERROR);

        return stringEncryptor.decrypt(encryptedMessage);
    }

}
