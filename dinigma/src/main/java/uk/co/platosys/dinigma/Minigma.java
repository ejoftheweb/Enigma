/*
 * Created 9 Dec 2016
 * www.platosys.co.uk 
 */
package uk.co.platosys.dinigma;

import java.io.ByteArrayInputStream;
import java.security.Provider;
import java.security.Security;
import java.util.Iterator;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import uk.co.platosys.dinigma.exceptions.MinigmaException;
import uk.co.platosys.dinigma.exceptions.SignatureException;
import uk.co.platosys.dinigma.exceptions.UnsupportedAlgorithmException;
import uk.co.platosys.dinigma.utils.MinigmaUtils;

/**
 * @author edward

 */
public class Minigma {
    public static String TAG = "Minigma";
    public  static final String PROVIDER_NAME = "SC";
    public static final int  HASH_ALGORITHM = HashAlgorithmTags.SHA512;
    public  static final int  COMPRESS_ALGORITHM = CompressionAlgorithmTags.UNCOMPRESSED;
    public static final int  STRONG_ALGORITHM = SymmetricKeyAlgorithmTags.AES_256;
    public static final int WEAK_ALGORITHM=SymmetricKeyAlgorithmTags.TRIPLE_DES;
    public static final Provider PROVIDER = initialiseProvider();
    public static final String LOCK_DIRNAME="lock";
    public static final String KEY_DIRNAME="key";

    /**
     * This takes an String and encrypts it with the given Lock
     * @param lock - the Lock with which to encrypt it;
     * @return
     * @throws MinigmaException
     */
    public static String lock(String clearString, Lock lock) throws MinigmaException{
        byte[] literalData=MinigmaUtils.toByteArray(clearString);
        byte[] compressedData = MinigmaUtils.compress(literalData);
        byte[] encryptedData=CryptoEngine.encrypt(compressedData, lock);
        return MinigmaUtils.encode(encryptedData);

    }

    /** This takes an EncryptedData String and returns  the cleartext
     * @return
     * @throws Exception
     */
    public static String unlock(String ciphertext, Key key, char[] passphrase) throws Exception {
        byte[] bytes = MinigmaUtils.decode(ciphertext);
        ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
        return CryptoEngine.decrypt(bais, key, passphrase);
    }
    /**
     * Returns a Base64-encoded String which is the signature of the passed-in String argument
     * signed with the passed-in Key.
     * @return
     * @throws MinigmaException
     */
    public static String sign(String string, Key key, char[] passphrase ) throws MinigmaException{
        return key.sign(string, passphrase);
    }

    public static long verify(String signedMaterial, String signature, LockStore lockStore)throws MinigmaException, UnsupportedAlgorithmException, SignatureException {
        Iterator<Lock> lockit = lockStore.iterator();
        while(lockit.hasNext()){
            Lock lock = lockit.next();
            if (lock.verify(signedMaterial, signature)){
                return lock.getLockID();
            }
        }
        return 0l;
    }



    //Private methods



    static Provider initialiseProvider(){
        Provider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        return provider;
    }



}

