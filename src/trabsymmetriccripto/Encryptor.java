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

            String charSet = "UTF-8";
            byte[] in = message.getBytes(charSet);
            byte[] out = cipher.doFinal(in);
            String encStr = new String(Base64.encodeBase64(out));
            return encStr;
        } catch (Exception e) {
            System.err.println(e);
        }

        return null;
    }

    public String decifrarMsg(SecretKey key, IvParameterSpec ivSpec, String message) throws Exception {
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

            byte[] enc = Base64.decodeBase64(message);
            byte[] utf8 = cipher.doFinal(enc);
            String charSet = "UTF-8";
            String plainStr = new String(utf8, charSet);

            return plainStr;
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            System.out.println(e);
        }

        return null;
    }
}
