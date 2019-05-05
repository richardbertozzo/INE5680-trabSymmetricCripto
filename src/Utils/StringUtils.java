package Utils;

import java.util.Scanner;
import javax.crypto.SecretKey;
import org.apache.commons.codec.binary.Hex;

public class StringUtils {

    public static byte[] toByteArray(String string) {
        byte[] bytes = new byte[string.length()];
        char[] chars = string.toCharArray();

        for (int i = 0; i != chars.length; i++) {
            bytes[i] = (byte) chars[i];
        }

        return bytes;
    }

    private static String toString(byte[] bytes, int length) {
        char[] chars = new char[length];

        for (int i = 0; i != chars.length; i++) {
            chars[i] = (char) (bytes[i] & 0xff);
        }

        return new String(chars);
    }

    public static String toString(byte[] bytes) {
        return toString(bytes, bytes.length);
    }

    public static String keyToString(SecretKey sk) {
        return Hex.encodeHexString(sk.getEncoded());
    }

    public static String getStringFromInput(String msg) {
        if (msg != null) {
            System.out.println(msg);
        }

        Scanner input = new Scanner(System.in);
        return input.nextLine();
    }

    /**
     * Return length many bytes of the passed in byte array as a hex string.
     *
     * @param data the bytes to be converted.
     * @param length the number of bytes in the data block to be converted.
     * @return a hex representation of length bytes of data.
     */
    private static String toHex(byte[] data, int length) {
        String digits = "0123456789abcdef";

        StringBuffer buf = new StringBuffer();

        for (int i = 0; i != length; i++) {
            int v = data[i] & 0xff;

            buf.append(digits.charAt(v >> 4));
            buf.append(digits.charAt(v & 0xf));
        }

        return buf.toString();
    }

    /**
     * Return the passed in byte array as a hex string.
     *
     * @param data the bytes to be converted.
     * @return a hex representation of data.
     */
    public static String toHex(byte[] data) {
        return toHex(data, data.length);
    }
}
