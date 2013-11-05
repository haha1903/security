package com.datayes.paas.spring;

import com.datayes.paas.Foo;
import com.datayes.paas.FooType;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.ObjectIdentityRetrievalStrategy;

/**
 * Created by changhai on 13-11-1.
 */
public class FooTypeObjectIdentityRetrievalStrategy implements ObjectIdentityRetrievalStrategy {
    @Override
    public ObjectIdentity getObjectIdentity(Object domainObject) {
        Foo foo = (Foo) domainObject;
        FooType fooType = new FooType();
        fooType.setId(foo.getType());
        return new ObjectIdentityImpl(fooType);
    }
}
