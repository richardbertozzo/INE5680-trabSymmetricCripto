package Utils;

import org.apache.commons.codec.binary.Hex;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class PBKDF2Util {

    public static SecretKey generateDerivedKey(String password, String salt, Integer iterations) {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), iterations, 128);

        try {
            SecretKeyFactory pbkdf2 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            SecretKey tmpSecretKey = pbkdf2.generateSecret(spec);

            return new SecretKeySpec(tmpSecretKey.getEncoded(), "AES");
        } catch (Exception e) {
            System.err.println(e);
            e.printStackTrace();
        }

        return null;
    }

    /*Usado para gerar o salt  */
    public static String getSalt() throws NoSuchAlgorithmException {
        SecureRandom sr = new SecureRandom();

        byte[] salt = new byte[16];
        sr.nextBytes(salt);

        return Hex.encodeHexString(salt);
    }
    
    public static byte[] getIv() throws NoSuchAlgorithmException, NoSuchProviderException {
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");

        byte[] ivBytes = new byte[16];
        random.nextBytes(ivBytes);

        return ivBytes;
    }
}
