package com.github.firststraw.jasypt;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.Provider;
import org.jasypt.encryption.pbe.config.PBEConfig;
import org.jasypt.encryption.pbe.config.SimplePBEConfig;
import org.jasypt.salt.SaltGenerator;
import org.jasypt.salt.StringFixedSaltGenerator;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Test;

/**
 * Tests the {@link JasyptPBEncryptor} class.
 */
public class JasyptPBEncryptorTest {

    private static final String PASSWORD = "@#lksjfa#$@%T";
    private static final String SALT = "1234567890123";

    private static final BigDecimal DECIMAL_MSG = new BigDecimal(10.0);
    private static final BigDecimal ENCRYPTED_DECIMAL_MSG =
            new BigDecimal("22994364563605601831629094920");

    private static final BigInteger INTEGER_MSG = new BigInteger("10");
    private static final BigInteger ENCRYPTED_INTEGER_MSG =
            new BigInteger("22994364563605601831629094920");

    private static final byte[] BYTE_MSG = new byte[]{100, 56, -125, 3};
    private static final byte[] ENCRYPTED_BYTE_MSG =
            new byte[]{-8, -54, 107, -14, -113, -26, 54, 38};

    private static final String STRING_MSG = "testmessage";
    private static final String ENCRYPTED_STRING_MSG = "ubIQyfUVsLvlWBj64qmiUw==";

    /**
     * Tests the
     * {@link JasyptPBEncryptor#JasyptPBEncryptor(org.jasypt.encryption.pbe.config.PBEConfig)}
     * constructor. Checks that when no {@link PBEConfig} is specified, then a
     * {@link NullPointerException} is thrown.
     */
    @Test(expected = NullPointerException.class)
    public void testConstructorNullConfig() {
        new JasyptPBEncryptor(null);
    }

    /**
     * Tests the
     * {@link JasyptPBEncryptor#JasyptPBEncryptor(org.jasypt.encryption.pbe.config.PBEConfig)}
     * constructor. Checks that when the pool size is invalid, then an
     * {@link IllegalArgumentException} is thrown.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testConstructorInvalidPoolSize() {
        getEncryptor(SALT, PASSWORD, 0, true);
    }

    /**
     * Tests the {@link JasyptPBEncryptor#encrypt(java.math.BigDecimal)} method. Checks that when
     * the message is {@code null}, then a {@link NullPointerException} is thrown.
     */
    @Test(expected = NullPointerException.class)
    public void testEncryptBigDecimalNullMessage() {
        getEncryptor(PASSWORD, SALT, null, true).encrypt((BigDecimal) null);
    }

    /**
     * Tests the {@link JasyptPBEncryptor#encrypt(java.math.BigInteger)} method. Checks that when
     * the message is {@code null}, then a {@link NullPointerException} is thrown.
     */
    @Test(expected = NullPointerException.class)
    public void testEncryptBigIntegerNullMessage() {
        getEncryptor(PASSWORD, SALT, null, true).encrypt((BigInteger) null);
    }

    /**
     * Tests the {@link JasyptPBEncryptor#encrypt(byte[])} method. Checks that when the message is
     * {@code null}, then a {@link NullPointerException} is thrown.
     */
    @Test(expected = NullPointerException.class)
    public void testEncryptBytesNullMessage() {
        getEncryptor(PASSWORD, SALT, null, true).encrypt((byte[]) null);
    }

    /**
     * Tests the {@link JasyptPBEncryptor#encrypt(byte[])} method. Checks that when the message is
     * empty, then an {@link IllegalArgumentException} is thrown.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testEncryptBytesEmptyMessage() {
        getEncryptor(PASSWORD, SALT, null, true).encrypt(new byte[0]);
    }

    /**
     * Tests the {@link JasyptPBEncryptor#encrypt(java.lang.String)} method. Checks that when the
     * message is {@code null}, then a {@link NullPointerException} is thrown.
     */
    @Test(expected = NullPointerException.class)
    public void testEncryptStringNullMessage() {
        getEncryptor(PASSWORD, SALT, null, true).encrypt((String) null);
    }

    /**
     * Tests the {@link JasyptPBEncryptor#encrypt(java.lang.String)} method. Checks that when the
     * message is empty, then an {@link IllegalArgumentException} is thrown.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testEncryptStringEmptyMessage() {
        getEncryptor(PASSWORD, SALT, null, true).encrypt("");
    }

    /**
     * Tests the {@link JasyptPBEncryptor#decrypt(java.math.BigDecimal)} method. Checks that when
     * the message is {@code null}, then a {@link NullPointerException} is thrown.
     */
    @Test(expected = NullPointerException.class)
    public void testDecryptBigDecimalNullMessage() {
        getEncryptor(PASSWORD, SALT, null, true).decrypt((BigDecimal) null);
    }

    /**
     * Tests the {@link JasyptPBEncryptor#decrypt(java.math.BigInteger)} method. Checks that when
     * the message is {@code null}, then a {@link NullPointerException} is thrown.
     */
    @Test(expected = NullPointerException.class)
    public void testDecryptBigIntegerNullMessage() {
        getEncryptor(PASSWORD, SALT, null, true).decrypt((BigInteger) null);
    }

    /**
     * Tests the {@link JasyptPBEncryptor#decrypt(byte[])} method. Checks that when the message is
     * {@code null}, then a {@link NullPointerException} is thrown.
     */
    @Test(expected = NullPointerException.class)
    public void testDecryptBytesNullMessage() {
        getEncryptor(PASSWORD, SALT, null, true).decrypt((byte[]) null);
    }

    /**
     * Tests the {@link JasyptPBEncryptor#decrypt(byte[])} method. Checks that when the message is
     * empty, then an {@link IllegalArgumentException} is thrown.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testDecryptBytesEmptyMessage() {
        getEncryptor(PASSWORD, SALT, null, true).decrypt(new byte[0]);
    }

    /**
     * Tests the {@link JasyptPBEncryptor#decrypt(java.lang.String)} method. Checks that when the
     * message is {@code null}, then a {@link NullPointerException} is thrown.
     */
    @Test(expected = NullPointerException.class)
    public void testDecryptStringNullMessage() {
        getEncryptor(PASSWORD, SALT, null, true).decrypt((String) null);
    }

    /**
     * Tests the {@link JasyptPBEncryptor#decrypt(java.lang.String)} method. Checks that when the
     * message is empty, then an {@link IllegalArgumentException} is thrown.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testDecryptStringEmptyMessage() {
        getEncryptor(PASSWORD, SALT, null, true).decrypt("");
    }

    /**
     * Tests encryption and decryption using "standard" encryptors when no pool size is specified.
     */
    @Test
    public void testStandardEncryptorsWithPoolSizeNull() {
        testEncryptors(getEncryptor(PASSWORD, SALT, null, true));
    }

    /**
     * Tests encryption and decryption using "standard" encryptors when the pool size is 1.
     */
    @Test
    public void testStandardEncryptorsWithPoolSize1() {
        testEncryptors(getEncryptor(PASSWORD, SALT, 1, true));
    }

    /**
     * Tests encryption and decryption using "pooled" encryptors.
     */
    @Test
    public void testPooledEncryptors() {
        testEncryptors(getEncryptor(PASSWORD, SALT, 2, false));
    }

    /**
     * Tests encryption and decryption using the specified encryptor.
     *
     * @param encryptor the encryptor to test encryption and decryption with
     */
    private static void testEncryptors(final JasyptPBEncryptor encryptor) {
        assertEquals(ENCRYPTED_DECIMAL_MSG, encryptor.encrypt(DECIMAL_MSG));
        assertEquals(ENCRYPTED_INTEGER_MSG, encryptor.encrypt(INTEGER_MSG));
        assertArrayEquals(ENCRYPTED_BYTE_MSG, encryptor.encrypt(BYTE_MSG));
        assertEquals(ENCRYPTED_STRING_MSG, encryptor.encrypt(STRING_MSG));
        assertEquals(DECIMAL_MSG, encryptor.decrypt(ENCRYPTED_DECIMAL_MSG));
        assertEquals(INTEGER_MSG, encryptor.decrypt(ENCRYPTED_INTEGER_MSG));
        assertArrayEquals(BYTE_MSG, encryptor.decrypt(ENCRYPTED_BYTE_MSG));
        assertEquals(STRING_MSG, encryptor.decrypt(ENCRYPTED_STRING_MSG));
    }

    /**
     * Creates a {@link JasyptPBEncryptor} with the specified configuration parameters.
     *
     * @param password encryption password
     * @param salt encryption salt
     * @param poolSize number of encryptors of each type to pool together for high-performance
     * encryption and decryption
     * @param cleanable {@code true} if a {@link SimplePBEConfig} should be used, otherwise an
     * anonymous implementation of {@link PBEConfig} will be used
     * @return the {@link JasyptPBEncryptor} configured with the specified configuration parameters
     */
    private static JasyptPBEncryptor getEncryptor(final String password, final String salt,
            final Integer poolSize, final boolean cleanable) {
        final SaltGenerator saltGen;
        if (salt == null) {
            saltGen = null;
        } else {
            saltGen = new StringFixedSaltGenerator(salt);
        }

        final PBEConfig config;
        if (cleanable) {
            final SimplePBEConfig simpleCfg = new SimplePBEConfig();
            simpleCfg.setPassword(password);
            simpleCfg.setSaltGenerator(saltGen);
            simpleCfg.setPoolSize(poolSize);

            config = simpleCfg;
        } else {
            config = new PBEConfig() {
                /**
                 * {@inheritDoc}
                 *
                 * @return {@inheritDoc}
                 */
                public String getAlgorithm() {
                    return null;
                }

                /**
                 * {@inheritDoc}
                 *
                 * @return {@inheritDoc}
                 */
                public String getPassword() {
                    return password;
                }

                /**
                 * {@inheritDoc}
                 *
                 * @return {@inheritDoc}
                 */
                public Integer getKeyObtentionIterations() {
                    return null;
                }

                /**
                 * {@inheritDoc}
                 *
                 * @return {@inheritDoc}
                 */
                public SaltGenerator getSaltGenerator() {
                    return saltGen;
                }

                /**
                 * {@inheritDoc}
                 *
                 * @return {@inheritDoc}
                 */
                public String getProviderName() {
                    return null;
                }

                /**
                 * {@inheritDoc}
                 *
                 * @return {@inheritDoc}
                 */
                public Provider getProvider() {
                    return null;
                }

                /**
                 * {@inheritDoc}
                 *
                 * @return {@inheritDoc}
                 */
                public Integer getPoolSize() {
                    return poolSize;
                }
            };
        }

        return new JasyptPBEncryptor(config);
    }

}
