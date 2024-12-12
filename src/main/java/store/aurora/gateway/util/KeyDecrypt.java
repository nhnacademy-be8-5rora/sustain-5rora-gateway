package store.aurora.gateway.util;

import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

@Component
public class KeyDecrypt {

    private final static String alg = "AES/CBC/PKCS5Padding";
    private final static String key = "MyTestCode-32CharacterTestAPIKey"; // todo : 따로 빼기
    private final static String iv = key.substring(0, 16);

    public String decrypt(String clientKey) {
        try {
            Cipher cipher = Cipher.getInstance(alg);
            SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "AES");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes());
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivParameterSpec);

            byte[] decoedBytes = Base64.getDecoder().decode(clientKey.getBytes());
            byte[] decrypted = cipher.doFinal(decoedBytes);
            return new String(decrypted).trim();
        } catch (Exception e) {
            throw new RuntimeException(String.format("복호화 처리중에 에러가 발생했습니다. e = %s", e.getMessage()));
        }
    }
}
