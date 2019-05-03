package Utils;

import org.apache.commons.codec.binary.Hex;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.SecretKey;

public class PBKDF2Util {

    /**
     * Gerar chave derivada da senha
     */
    public static SecretKey generateDerivedKey(String password, String salt, Integer iterations) {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), iterations, 128);

        try {
            SecretKeyFactory pbkdf2 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return pbkdf2.generateSecret(spec);
        } catch (Exception e) {
            System.err.println(e);
            e.printStackTrace();
        }

        return null;
    }

    /*Usado para gerar o salt  */
    public String getSalt() throws NoSuchAlgorithmException {
        SecureRandom sr = new SecureRandom();

        byte[] salt = new byte[16];
        sr.nextBytes(salt);

        return Hex.encodeHexString(salt);
    }
}
