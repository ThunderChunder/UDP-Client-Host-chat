import javax.crypto.spec.*;
import java.security.*;
import javax.crypto.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.Base64.*;

public class rc4
{
   private final static String algorithm = "RC4";
  
   public static byte[] encrypt(String toEncrypt, String key) throws Exception 
   {
      Cipher cipher = Cipher.getInstance(algorithm);
      SecretKeySpec sk = new SecretKeySpec(key.getBytes(), algorithm); 
      cipher.init(Cipher.ENCRYPT_MODE, sk);
      byte [] encrypted = cipher.update(toEncrypt.getBytes());
  
      return Base64.getEncoder().encode(encrypted);
   }
  
   public static String decrypt(byte[] toDecrypt, String key) throws Exception 
   {
      Cipher cipher = Cipher.getInstance(algorithm);
      SecretKeySpec sk = new SecretKeySpec(key.getBytes(), algorithm);
      cipher.init(Cipher.DECRYPT_MODE, sk);
      byte[] decrypted = Base64.getMimeDecoder().decode(toDecrypt);
      decrypted = cipher.update(decrypted);

      return new String(decrypted);
   }
}
