package trabsymmetriccripto;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

public class Encryptor {

    private final Cipher cipher;

    public Encryptor() throws Exception {
        cipher = Cipher.getInstance("AES/CTR/NoPadding");
    }

    public String cifrarMsg(SecretKeySpec key, IvParameterSpec iv, String message) {
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);

            byte[] decodeHex = Base64.decodeBase64(message);
            
            byte[] encrypted = cipher.doFinal(decodeHex);

            return Base64.encodeBase64String(encrypted);
        } catch (Exception e) {
            System.err.println(e);
        }

        return null;
    }

    public String decifrarMsg(SecretKey key, IvParameterSpec ivSpec, String message) throws Exception {
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
            
            byte[] decodeHex = Base64.decodeBase64(message);

            byte[] original = cipher.doFinal(decodeHex);

            return Base64.encodeBase64String(original);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            System.out.println(e);
        }

        return null;
    }
}
