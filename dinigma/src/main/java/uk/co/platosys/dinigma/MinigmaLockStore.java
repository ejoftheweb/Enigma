
/* Created on Jan 30, 2006
        * (c) copyright 2017 Platosys
        * MIT Licence
        
        * This is an implementation of the Lockstore interface that uses the OpenPGP public key ring format to store keys
        *
        *
        *
        */
        package uk.co.platosys.dinigma;


        import java.io.File;
        import java.io.FileInputStream;
        import java.io.FileOutputStream;
        import java.io.InputStream;
        import java.io.OutputStream;
        import java.util.ArrayList;
        import java.util.Collection;
        import java.util.Iterator;
        import java.util.List;

        import org.bouncycastle.bcpg.ArmoredInputStream;
        import org.bouncycastle.bcpg.ArmoredOutputStream;
        import org.bouncycastle.openpgp.PGPPublicKey;
        import org.bouncycastle.openpgp.PGPPublicKeyRing;
        import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
        import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
        import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

        import uk.co.platosys.dinigma.exceptions.MinigmaException;


/**
 * @author edward
 * The LockStore class wraps OpenPGP public keyrrings
 *
 *
 */
public class MinigmaLockStore implements LockStore {
    private static String TAG = "LockStore";
    private PGPPublicKeyRingCollection keyRings;
    private PGPPublicKeyRing pgpPublicKeyRing;
    private File file;
    private long storeId;

    public MinigmaLockStore(File file) throws MinigmaException{
        this.file=file;
        if (file.exists()&&file.canRead()){
            if (!load()){
                throw new MinigmaException("LockStore-init failed at loading");
            }


        }else{
            throw new MinigmaException( "LockStore-init: file doesn't exist");
        }
    }

    private  boolean load() throws MinigmaException{
        try {
            InputStream keyIn = new ArmoredInputStream(new FileInputStream(file));
            KeyFingerPrintCalculator calculator = new JcaKeyFingerprintCalculator();
            keyRings=new PGPPublicKeyRingCollection(keyIn, calculator);
            PGPPublicKey publicKey = null;
            Iterator<PGPPublicKeyRing> ringIterator = keyRings.getKeyRings();
            while (ringIterator.hasNext() && publicKey==null){
                PGPPublicKeyRing thisKeyRing=(PGPPublicKeyRing)ringIterator.next();
                Iterator<PGPPublicKey> keyIterator = thisKeyRing.getPublicKeys();
                while(keyIterator.hasNext() && publicKey==null){
                    PGPPublicKey testKey = (PGPPublicKey)keyIterator.next();
                    if (testKey.isEncryptionKey()){
                        publicKey=testKey;
                        pgpPublicKeyRing=thisKeyRing;

                    }
                }
                this.storeId=publicKey.getKeyID();
            }

            //encryptionLock=new Lock(publicKey);
            return true;
        }catch(Exception e){
            throw new MinigmaException ("Lockstore: load failed", e);
        }
    }
    private boolean save(){
        try {
            OutputStream outStream = new ArmoredOutputStream(new FileOutputStream(file));
            keyRings.encode(outStream);
            outStream.close();
            return true;
        }catch(Exception e){
             return false;
        }
    }

    public boolean saveAs(File file){
        this.file=file;
        return save();
    }

    @Override
    public boolean addLock(Lock lock){
        try {
            if (keyRings==null){
                load();
            }
            Iterator<PGPPublicKeyRing> it = lock.getKeys();

            while (it.hasNext()){
                PGPPublicKeyRing publicKey =  it.next();
                keyRings = PGPPublicKeyRingCollection.addPublicKeyRing(keyRings, publicKey);
            }
            return save();
        }catch(Exception e){
            return false;
        }
    }

    /** @param keyID
     * @return a lock with this keyID */
    @Override
    public Lock getLock(long keyID){
        try{
            PGPPublicKeyRing keyRing = keyRings.getPublicKeyRing(keyID);
            Collection<PGPPublicKeyRing> collection = new ArrayList<>();
            collection.add(keyRing);
            PGPPublicKeyRingCollection keyRingCollection = new PGPPublicKeyRingCollection(collection);
            return new Lock(keyRingCollection);
        }catch(Exception e){
            return null;
        }
    }
    @Override
    public Iterator<Lock> iterator() throws MinigmaException{
        List<Lock> list = new ArrayList<>();
        try{
            Iterator<PGPPublicKeyRing> kringit = keyRings.getKeyRings();
            while(kringit.hasNext()){
                Collection<PGPPublicKeyRing> collection = new ArrayList<>();
                collection.add(kringit.next());
                PGPPublicKeyRingCollection keyRingCollection = new PGPPublicKeyRingCollection(collection);
                list.add(new Lock(keyRingCollection));
            }
        }catch(Exception e){
            throw new MinigmaException("problem creating lockstore iterator");
        }
        return list.iterator();
    }
    /** returns */
    @Override
    public Lock getLock(String userID)throws MinigmaException{
        try{
            PGPPublicKeyRingCollection keyRingCollection=null;
            Iterator<PGPPublicKeyRing> itr = keyRings.getKeyRings(userID, true);
            while(itr.hasNext() ){
                PGPPublicKeyRing publicKeyRing=itr.next();
                if (keyRingCollection==null){
                    Collection<PGPPublicKeyRing> collection = new ArrayList<>();
                    collection.add(publicKeyRing);
                    keyRingCollection=new PGPPublicKeyRingCollection(collection);
                }else{
                    keyRingCollection=PGPPublicKeyRingCollection.addPublicKeyRing(keyRingCollection,publicKeyRing);
                }
            }
            return new Lock(keyRingCollection);
        }catch(Exception e){
            throw new MinigmaException("error getting lock for userID "+userID, e);
        }
    }
    /**
     *
     */
    @Override
    public long getStoreId(){
        return storeId;
    }

}