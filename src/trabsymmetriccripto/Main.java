package trabsymmetriccripto;

import Utils.PBKDF2Util;
import Utils.StringUtils;
import java.security.NoSuchAlgorithmException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Main {

    public static void main(String[] args) throws NoSuchAlgorithmException, Exception {
        PBKDF2Util pbdk2Util = new PBKDF2Util();
        Encryptor cripto = new Encryptor();

        // Key Store
        String fileName = "keystore.bcfks";
        String masterPassword = StringUtils.getPasswordFromInput("Digite a senha mestre: ");
        KeyStoreAdapter keyStore = new KeyStoreAdapter(masterPassword, fileName);

        // gerando salt
        String salt = pbdk2Util.getSalt();
        System.err.println("Salt: " + salt);

        String password = StringUtils.getPasswordFromInput("Digite a senha: ");
        String aliasKey = StringUtils.getPasswordFromInput("Digite um alias para guardar sua chave (ex: senha1): ");

        SecretKey generateDerivedKey = PBKDF2Util.generateDerivedKey(password, salt, 10000);
        System.err.println("Key: " + StringUtils.keyToString(generateDerivedKey));

        keyStore.storeSecretKey(password, generateDerivedKey, aliasKey);
        keyStore.printKeyStore();

        SecretKey key2 = keyStore.getSecretKey(aliasKey, password);

        String message = "Mensagem teste";
        IvParameterSpec iv = pbdk2Util.getIv();
        String cifrarMsg = cripto.cifrarMsg((SecretKeySpec) generateDerivedKey, iv, message);
        System.out.println("encrypted message: " + cifrarMsg);

        
        String decifrada = cripto.decifrarMsg((SecretKeySpec) generateDerivedKey, iv, cifrarMsg);
        System.err.println("Decifrada: " + decifrada);
    }
}
