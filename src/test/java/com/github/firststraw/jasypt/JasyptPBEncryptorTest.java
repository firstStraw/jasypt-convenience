package com.github.firststraw.jasypt;

import java.math.BigDecimal;
import java.math.BigInteger;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Test;

/**
 * Tests the {@link JasyptPBEncryptor} class.
 */
public class JasyptPBEncryptorTest {

    private static final String PASSWORD = "@#lksjfa#$@%T";
    private static final String SALT = "1234567890123";

    /**
     * Tests the {@link JasyptPBEncryptor#JasyptPBEncryptor(java.lang.String, java.lang.String)}
     * constructor. Checks that when the password is {@code null}, then a
     * {@link NullPointerException} is thrown.
     */
    @Test(expected = NullPointerException.class)
    public void testConstructorNullPassword() {
        getEncryptor(null, SALT);
    }

    /**
     * Tests the {@link JasyptPBEncryptor#JasyptPBEncryptor(java.lang.String, java.lang.String)}
     * constructor. Checks that when the password is empty, then an {@link IllegalArgumentException}
     * is thrown.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testConstructorEmptyPassword() {
        getEncryptor("", SALT);
    }

    /**
     * Tests the {@link JasyptPBEncryptor#JasyptPBEncryptor(java.lang.String, java.lang.String)}
     * constructor. Checks that when the salt is {@code null}, then a {@link NullPointerException}
     * is thrown.
     */
    @Test(expected = NullPointerException.class)
    public void testConstructorNullSalt() {
        getEncryptor(PASSWORD, null);
    }

    /**
     * Tests the {@link JasyptPBEncryptor#JasyptPBEncryptor(java.lang.String, java.lang.String)}
     * constructor. Checks that when the salt is empty, then an {@link IllegalArgumentException} is
     * thrown.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testConstructorEmptySalt() {
        getEncryptor(PASSWORD, "");
    }

    /**
     * Tests the {@link JasyptPBEncryptor#encrypt(java.math.BigDecimal)} method. Checks that when
     * the message is {@code null}, then a {@link NullPointerException} is thrown.
     */
    @Test(expected = NullPointerException.class)
    public void testEncryptBigDecimalNullMessage() {
        getEncryptor().encrypt((BigDecimal) null);
    }

    /**
     * Tests the {@link JasyptPBEncryptor#encrypt(java.math.BigDecimal)} method. Checks that the
     * {@link BigDecimal} is encrypted correctly.
     */
    @Test
    public void testEncryptBigDecimal() {
        final BigDecimal message = new BigDecimal(10.0);
        final BigDecimal expected = new BigDecimal("22994364563605601831629094920");

        assertEquals(expected, getEncryptor().encrypt(message));
    }

    /**
     * Tests the {@link JasyptPBEncryptor#encrypt(java.math.BigInteger)} method. Checks that when
     * the message is {@code null}, then a {@link NullPointerException} is thrown.
     */
    @Test(expected = NullPointerException.class)
    public void testEncryptBigIntegerNullMessage() {
        getEncryptor().encrypt((BigInteger) null);
    }

    /**
     * Tests the {@link JasyptPBEncryptor#encrypt(java.math.BigInteger)} method. Checks that the
     * {@link BigInteger} is encrypted correctly.
     */
    @Test
    public void testEncryptBigInteger() {
        final BigInteger message = new BigInteger("10");
        final BigInteger expected = new BigInteger("22994364563605601831629094920");

        assertEquals(expected, getEncryptor().encrypt(message));
    }

    /**
     * Tests the {@link JasyptPBEncryptor#encrypt(byte[])} method. Checks that when the message is
     * {@code null}, then a {@link NullPointerException} is thrown.
     */
    @Test(expected = NullPointerException.class)
    public void testEncryptBytesNullMessage() {
        getEncryptor().encrypt((byte[]) null);
    }

    /**
     * Tests the {@link JasyptPBEncryptor#encrypt(byte[])} method. Checks that when the message is
     * empty, then an {@link IllegalArgumentException} is thrown.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testEncryptBytesEmptyMessage() {
        getEncryptor().encrypt(new byte[0]);
    }

    /**
     * Tests the {@link JasyptPBEncryptor#encrypt(byte[])} method. Checks that the {@link byte}s are
     * encrypted correctly.
     */
    @Test
    public void testEncryptBytes() {
        final byte[] message = new byte[]{100, 56, -125, 3};
        final byte[] expected = new byte[]{-8, -54, 107, -14, -113, -26, 54, 38};

        assertArrayEquals(expected, getEncryptor().encrypt(message));
    }

    /**
     * Tests the {@link JasyptPBEncryptor#encrypt(java.lang.String)} method. Checks that when the
     * message is {@code null}, then a {@link NullPointerException} is thrown.
     */
    @Test(expected = NullPointerException.class)
    public void testEncryptStringNullMessage() {
        getEncryptor().encrypt((String) null);
    }

    /**
     * Tests the {@link JasyptPBEncryptor#encrypt(java.lang.String)} method. Checks that when the
     * message is empty, then an {@link IllegalArgumentException} is thrown.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testEncryptStringEmptyMessage() {
        getEncryptor().encrypt("");
    }

    /**
     * Tests the {@link JasyptPBEncryptor#encrypt(java.lang.String)} method. Checks that the
     * {@link String} is encrypted correctly.
     */
    @Test
    public void testEncryptString() {
        final String message = "testmessage";
        final String expected = "ubIQyfUVsLvlWBj64qmiUw==";

        assertEquals(expected, getEncryptor().encrypt(message));
    }

    /**
     * Tests the {@link JasyptPBEncryptor#decrypt(java.math.BigDecimal)} method. Checks that when
     * the message is {@code null}, then a {@link NullPointerException} is thrown.
     */
    @Test(expected = NullPointerException.class)
    public void testDecryptBigDecimalNullMessage() {
        getEncryptor().decrypt((BigDecimal) null);
    }

    /**
     * Tests the {@link JasyptPBEncryptor#decrypt(java.math.BigDecimal)} method. Checks that the
     * {@link BigDecimal} is decrypted correctly.
     */
    @Test
    public void testDecryptBigDecimal() {
        final BigDecimal expected = new BigDecimal(10.0);
        final BigDecimal encryptedMessage = new BigDecimal("22994364563605601831629094920");

        assertEquals(expected, getEncryptor().decrypt(encryptedMessage));
    }

    /**
     * Tests the {@link JasyptPBEncryptor#decrypt(java.math.BigInteger)} method. Checks that when
     * the message is {@code null}, then a {@link NullPointerException} is thrown.
     */
    @Test(expected = NullPointerException.class)
    public void testDecryptBigIntegerNullMessage() {
        getEncryptor().decrypt((BigInteger) null);
    }

    /**
     * Tests the {@link JasyptPBEncryptor#decrypt(java.math.BigInteger)} method. Checks that the
     * {@link BigInteger} is decrypted correctly.
     */
    @Test
    public void testDecryptBigInteger() {
        final BigInteger expected = new BigInteger("10");
        final BigInteger encryptedMessage = new BigInteger("22994364563605601831629094920");

        assertEquals(expected, getEncryptor().decrypt(encryptedMessage));
    }

    /**
     * Tests the {@link JasyptPBEncryptor#decrypt(byte[])} method. Checks that when the message is
     * {@code null}, then a {@link NullPointerException} is thrown.
     */
    @Test(expected = NullPointerException.class)
    public void testDecryptBytesNullMessage() {
        getEncryptor().decrypt((byte[]) null);
    }

    /**
     * Tests the {@link JasyptPBEncryptor#decrypt(byte[])} method. Checks that when the message is
     * empty, then an {@link IllegalArgumentException} is thrown.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testDecryptBytesEmptyMessage() {
        getEncryptor().decrypt(new byte[0]);
    }

    /**
     * Tests the {@link JasyptPBEncryptor#decrypt(byte[])} method. Checks that the bytes are
     * decrypted correctly.
     */
    @Test
    public void testDecryptBytes() {
        final byte[] expected = new byte[]{100, 56, -125, 3};
        final byte[] encryptedMessage = new byte[]{-8, -54, 107, -14, -113, -26, 54, 38};

        assertArrayEquals(expected, getEncryptor().decrypt(encryptedMessage));
    }

    /**
     * Tests the {@link JasyptPBEncryptor#decrypt(java.lang.String)} method. Checks that when the
     * message is {@code null}, then a {@link NullPointerException} is thrown.
     */
    @Test(expected = NullPointerException.class)
    public void testDecryptStringNullMessage() {
        getEncryptor().decrypt((String) null);
    }

    /**
     * Tests the {@link JasyptPBEncryptor#decrypt(java.lang.String)} method. Checks that when the
     * message is empty, then an {@link IllegalArgumentException} is thrown.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testDecryptStringEmptyMessage() {
        getEncryptor().decrypt("");
    }

    /**
     * Tests the {@link JasyptPBEncryptor#decrypt(java.lang.String)}. Checks that the {@link String}
     * is decrypted correctly.
     */
    @Test
    public void testDecryptString() {
        final String expected = "testmessage";
        final String encryptedMessage = "ubIQyfUVsLvlWBj64qmiUw==";

        assertEquals(expected, getEncryptor().decrypt(encryptedMessage));
    }

    /**
     * Builds an encryptor with the password and salt used for testing.
     *
     * @return the {@link JasyptPBEncryptor} initialized with the password and salt used for testing
     */
    private JasyptPBEncryptor getEncryptor() {
        return getEncryptor(PASSWORD, SALT);
    }

    /**
     * Builds an encryptor with the specified password and salt.
     *
     * @param password the password to initialize the encryptor with
     * @param salt the salt to initialize the encryptor with
     * @return the {@link JasyptPBEncryptor} initialized with the specified password and salt
     */
    private JasyptPBEncryptor getEncryptor(final String password, final String salt) {
        return new JasyptPBEncryptor(password, salt);
    }

}
