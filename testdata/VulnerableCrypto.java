import java.security.*;
import java.security.spec.RSAKeyGenParameterSpec;
import javax.crypto.*;
import java.math.BigInteger;

public class VulnerableCrypto {

    // RSA key generation — quantum-vulnerable
    public KeyPair generateRSAKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(new RSAKeyGenParameterSpec(1024, BigInteger.valueOf(65537)));
        return kpg.generateKeyPair();
    }

    // RSA encryption
    public byte[] encryptRSA(PublicKey pub, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, pub);
        return cipher.doFinal(data);
    }

    // ECDH key agreement — quantum-vulnerable
    public byte[] ecdhKeyAgreement(PrivateKey priv, PublicKey pub) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(priv);
        ka.doPhase(pub, true);
        return ka.generateSecret();
    }

    // ECDSA signing — quantum-vulnerable
    public byte[] ecdsaSign(PrivateKey priv, byte[] data) throws Exception {
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(priv);
        sig.update(data);
        return sig.sign();
    }

    // AES in ECB mode — insecure mode
    public byte[] encryptAESECB(SecretKey key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    // AES with no mode — defaults to ECB on most JVMs
    public byte[] encryptAESDefault(SecretKey key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    // Triple DES — deprecated
    public byte[] encryptTripleDES(SecretKey key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    // RC4 — broken stream cipher
    public byte[] encryptRC4(SecretKey key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("RC4");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    // MD5 — collision-broken
    public byte[] hashMD5(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(data);
    }

    // SHA-1 — deprecated
    public byte[] hashSHA1(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        return md.digest(data);
    }

    // SHA1withRSA — double vulnerability
    public byte[] signSHA1withRSA(PrivateKey priv, byte[] data) throws Exception {
        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initSign(priv);
        sig.update(data);
        return sig.sign();
    }
}
