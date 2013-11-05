package com.datayes.paas.spring.time;

import org.springframework.security.acls.domain.AclAuthorizationStrategy;
import org.springframework.security.acls.domain.AclImpl;
import org.springframework.security.acls.domain.AuditLogger;
import org.springframework.security.acls.model.*;
import org.springframework.util.Assert;

import java.io.Serializable;
import java.lang.reflect.Field;
import java.sql.Date;
import java.util.List;

public class TimeAcl extends AclImpl {
    private transient AclAuthorizationStrategy aclAuthorizationStrategy;

    public TimeAcl(ObjectIdentity objectIdentity, Serializable id, AclAuthorizationStrategy aclAuthorizationStrategy,
                   AuditLogger auditLogger) {
        super(objectIdentity, id, aclAuthorizationStrategy, auditLogger);
        this.aclAuthorizationStrategy = aclAuthorizationStrategy;
    }

    public TimeAcl(ObjectIdentity objectIdentity, Serializable id, AclAuthorizationStrategy aclAuthorizationStrategy,
                   PermissionGrantingStrategy grantingStrategy, Acl parentAcl, List<Sid> loadedSids, boolean entriesInheriting, Sid owner) {
        super(objectIdentity, id, aclAuthorizationStrategy, grantingStrategy, parentAcl, loadedSids, entriesInheriting, owner);
        this.aclAuthorizationStrategy = aclAuthorizationStrategy;
    }

    public void insertAce(int atIndexLocation, Permission permission, Sid sid, boolean granting, Date start, Date end) throws NotFoundException {
        aclAuthorizationStrategy.securityCheck(this, AclAuthorizationStrategy.CHANGE_GENERAL);
        Assert.notNull(permission, "Permission required");
        Assert.notNull(sid, "Sid required");
        if (atIndexLocation < 0) {
            throw new NotFoundException("atIndexLocation must be greater than or equal to zero");
        }
        List<AccessControlEntry> aces = this.getAces();
        if (atIndexLocation > aces.size()) {
            throw new NotFoundException("atIndexLocation must be less than or equal to the size of the AccessControlEntry collection");
        }

        TimeAccessControlEntryImpl ace = new TimeAccessControlEntryImpl(null, this, sid, permission, granting, false, false);
        ace.setStart(start);
        ace.setEnd(end);

        synchronized (aces) {
            aces.add(atIndexLocation, ace);
        }
    }

    private List<AccessControlEntry> getAces() {
        try {
            Field acesField = AclImpl.class.getDeclaredField("aces");
            acesField.setAccessible(true);
            return (List<AccessControlEntry>) acesField.get(this);
        } catch (NoSuchFieldException e) {
            throw new RuntimeException(e);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }
}
