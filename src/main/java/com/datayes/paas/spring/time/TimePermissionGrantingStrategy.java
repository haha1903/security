package com.datayes.paas.spring.time;

import org.springframework.security.acls.domain.AuditLogger;
import org.springframework.security.acls.domain.DefaultPermissionGrantingStrategy;
import org.springframework.security.acls.model.*;

import java.util.Date;
import java.util.List;

/**
 * Created by changhai on 13-11-5.
 */
public class TimePermissionGrantingStrategy extends DefaultPermissionGrantingStrategy {
    /**
     * Creates an instance with the logger which will be used to record granting and denial of requested permissions.
     *
     * @param auditLogger
     */
    public TimePermissionGrantingStrategy(AuditLogger auditLogger) {
        super(auditLogger);
    }

    @Override
    public boolean isGranted(Acl acl, List<Permission> permission, List<Sid> sids, boolean administrativeMode) throws NotFoundException {
        List<AccessControlEntry> entries = acl.getEntries();
        for (AccessControlEntry accessControlEntry : entries) {
            if (accessControlEntry instanceof TimeAccessControlEntryImpl) {
                TimeAccessControlEntryImpl timeAccessControlEntry = (TimeAccessControlEntryImpl) accessControlEntry;
                Date now = new Date();
                Date end = timeAccessControlEntry.getEnd();
                Date start = timeAccessControlEntry.getStart();
                if((start != null && now.before(start)) || (end != null && now.after(end)))
                    return false;
            }
        }
        return super.isGranted(acl, permission, sids, administrativeMode);
    }
}
