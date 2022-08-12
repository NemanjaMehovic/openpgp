package etf.openpgp.mn180452d;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.*;
import org.bouncycastle.openpgp.operator.jcajce.*;

import java.io.*;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.*;

public class Keys
{
    public enum RSA_Key_Size{
        RSA1024(1024),
        RSA2048(2048),
        RSA4096(4096);

        public int enumVal;

        RSA_Key_Size(int val)
        {
            enumVal = val;
        }
    }

    public class KeyData{
        public PGPKeyPair keyPair;
        public String userId;
        public String password;

        public KeyData(PGPKeyPair keyPair, String userId, String password)
        {
            this.keyPair = keyPair;
            this.userId = userId;
            this.password = password;
        }
    }

    private static Keys instance = null;

    private Keys()
    {
        allKeys = new ArrayList<>();
    }

    public static Keys getInstance()
    {
        if(instance == null)
            instance = new Keys();
        return instance;
    }

    private List<KeyData> allKeys;
    public PGPSecretKeyRing importedSecretKeyRing;

    public List<KeyData> getAllKeys()
    {
        return allKeys;
    }

    public KeyData GenerateNewKeyPair(String userId, String password, RSA_Key_Size keySize) throws NoSuchProviderException, NoSuchAlgorithmException, PGPException
    {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(keySize.enumVal);
        PGPKeyPair keyPair = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, generator.generateKeyPair(), new Date());
        KeyData data = new KeyData(keyPair, userId, password);
        allKeys.add(data);
        return data;
    }

    private PGPSecretKey GetSecretKey(KeyData keyData) throws PGPException
    {
        PGPDigestCalculator calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
        PGPContentSignerBuilder signerBuilder = new JcaPGPContentSignerBuilder(keyData.keyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1);
        PBESecretKeyEncryptor secretKeyEncryptor = null;
        if(keyData.password != null)
            secretKeyEncryptor = new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_128, calc).setProvider("BC").build(keyData.password.toCharArray());
        return new PGPSecretKey(PGPSignature.DEFAULT_CERTIFICATION, keyData.keyPair, keyData.userId, calc, null, null, signerBuilder, secretKeyEncryptor);
    }

    public void ExportPrivateKey(KeyData keyData, String FileName) throws IOException, PGPException
    {
        PGPSecretKey key = GetSecretKey(keyData);
        OutputStream file = new FileOutputStream(FileName);
        OutputStream outputStream = new ArmoredOutputStream(file);
        key.encode(outputStream);
        outputStream.close();
        file.close();
    }

    public void ExportPublicKey(KeyData keyData, String FileName) throws IOException, PGPException
    {
        PGPSecretKey key = GetSecretKey(keyData);
        OutputStream file = new FileOutputStream(FileName);
        OutputStream outputStream = new ArmoredOutputStream(file);
        key.getPublicKey().encode(outputStream);
        outputStream.close();
        file.close();
    }

    public boolean ImportKey(String FileName) throws Exception
    {
        importedSecretKeyRing = null;
        InputStream in = PGPUtil.getDecoderStream(new FileInputStream(FileName));
        JcaPGPObjectFactory factory = new JcaPGPObjectFactory(in);
        Object obj = factory.nextObject();
        if(obj instanceof PGPSecretKeyRing)
        {
            in.close();
            importedSecretKeyRing = (PGPSecretKeyRing) obj;
            try
            {
                PGPSecretKey tmpSecretKey = importedSecretKeyRing.getSecretKey();
                tmpSecretKey.extractKeyPair(null);
                ImportPrivateKey(importedSecretKeyRing, null);
                return false;
            }
            catch (Exception ex)
            {
                return true;
            }
        }
        else if(obj instanceof PGPPublicKeyRing)
        {
            while(obj instanceof  PGPPublicKeyRing)
            {
                ImportPublicKey((PGPPublicKeyRing) obj);
                obj = factory.nextObject();
            }
            in.close();
            return false;
        }
        throw new Exception("File does not contain a key.");
    }

    public void ImportPrivateKey(PGPSecretKeyRing keyRing, String keyPassword) throws Exception
    {
        PBESecretKeyDecryptor decryptor = null;
        if(keyPassword != null)
            decryptor = new JcePBESecretKeyDecryptorBuilder(new JcaPGPDigestCalculatorProviderBuilder().build()).build(keyPassword.toCharArray());
        String UserId = keyRing.getPublicKey().getUserIDs().next();
        Iterator<PGPSecretKey> it = keyRing.getSecretKeys();
        while(it.hasNext())
        {
            PGPSecretKey secretKey = (PGPSecretKey) it.next();
            PGPKeyPair keyPair = secretKey.extractKeyPair(decryptor);
            for(int i = 0; i < allKeys.size(); i++)
                if(allKeys.get(i).keyPair.getKeyID() == keyPair.getKeyID())
                {
                    allKeys.remove(i);
                    i--;
                }
            allKeys.add(new KeyData(keyPair, UserId, keyPassword));
        }
    }

    public void ImportPublicKey(PGPPublicKeyRing keyRing) throws Exception
    {
        String userId = keyRing.getPublicKey().getUserIDs().next();
        Iterator<PGPPublicKey> it = keyRing.getPublicKeys();
        while(it.hasNext())
        {
            try
            {
                PGPPublicKey publicKey = it.next();
                for (KeyData data : allKeys)
                    if (data.keyPair.getKeyID() == publicKey.getKeyID())
                        throw new Exception("Already contains key with keyId " + publicKey.getKeyID());
                PGPKeyPair keyPair = new PGPKeyPair(publicKey, null);
                allKeys.add(new KeyData(keyPair, userId, null));
            }
            catch (Exception ignored){}
        }
    }
}
