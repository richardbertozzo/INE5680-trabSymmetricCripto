package trabsymmetriccripto;

import Utils.PBKDF2Util;
import Utils.StringUtils;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;
import javax.crypto.SecretKey;

public class Main {

    private static void saveKey() {

    }

    private static void cifrarMsg() {

    }

    private static String decifrarMsg() {
        return "";
    }

    private static String getPasswordFromInput(String msg) {
        Scanner input = new Scanner(System.in);
        System.out.println(msg);
        return input.nextLine();
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, Exception {
        PBKDF2Util pbdk2Util = new PBKDF2Util();

        // Key Store
        String fileName = "keystore.bcfks";
        String masterPassword = getPasswordFromInput("Digite a senha mestre: ");
        KeyStoreAdapter keyStore = new KeyStoreAdapter(masterPassword, fileName);

        // gerando salt
        String salt = pbdk2Util.getSalt();
        System.err.println("Salt: " + salt);

        String password = getPasswordFromInput("Digite a senha: ");
        String aliasKey = getPasswordFromInput("Digite um alias para guardar sua chave (ex: senha1): ");

        SecretKey generateDerivedKey = PBKDF2Util.generateDerivedKey(password, salt, 10000);
        System.err.println("Key: " + StringUtils.keyToString(generateDerivedKey));

        keyStore.storeSecretKey(password, generateDerivedKey, aliasKey);
        keyStore.printKeyStore();

        SecretKey key2 = keyStore.getSecretKey(aliasKey, password);
        System.err.println("Get key: " + StringUtils.keyToString(key2));
    }
}
