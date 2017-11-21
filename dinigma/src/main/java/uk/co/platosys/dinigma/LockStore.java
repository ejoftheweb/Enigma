package uk.co.platosys.dinigma;

import uk.co.platosys.dinigma.exceptions.MinigmaException;

import java.util.Iterator;

public interface LockStore {
    boolean addLock(Lock lock);

    Lock getLock(long keyID);

    Iterator<Lock> iterator() throws MinigmaException;

    Lock getLock(String userID)throws MinigmaException;

    long getStoreId();
}
