package com.datayes.paas.spring;

import org.springframework.security.acls.model.AclCache;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.ObjectIdentity;

import java.io.Serializable;

/**
 * Created by changhai on 13-11-7.
 */
public class NullAclCache implements AclCache {
    @Override
    public void evictFromCache(Serializable pk) {
    }

    @Override
    public void evictFromCache(ObjectIdentity objectIdentity) {
    }

    @Override
    public MutableAcl getFromCache(ObjectIdentity objectIdentity) {
        return null;
    }

    @Override
    public MutableAcl getFromCache(Serializable pk) {
        return null;
    }

    @Override
    public void putInCache(MutableAcl acl) {
    }

    @Override
    public void clearCache() {
    }
}
