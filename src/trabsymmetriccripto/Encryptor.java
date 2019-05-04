package trabsymmetriccripto;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

import org.apache.commons.codec.binary.Base64;

public class Encryptor {

    private final Cipher cipher;

    public Encryptor() throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
        // Install Provider FIPS
        Security.addProvider(new BouncyCastleFipsProvider());

        this.cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BCFIPS");
    }

    public String cifrarMsg(SecretKeySpec key, IvParameterSpec iv, String message) {
        try {
            this.cipher.init(Cipher.ENCRYPT_MODE, key, iv);

            byte[] encrypted = cipher.doFinal(message.getBytes());

            return Base64.encodeBase64String(encrypted);
        } catch (Exception e) {
            System.err.println(e);
        }

        return null;
    }

    public String decifrarMsg(SecretKeySpec key, IvParameterSpec ivSpec, String message) throws Exception {
        try {
            this.cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

            byte[] original = cipher.doFinal(Base64.decodeBase64(message));

            return new String(original);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            System.out.println(e);
        }

        return null;
    }
}
