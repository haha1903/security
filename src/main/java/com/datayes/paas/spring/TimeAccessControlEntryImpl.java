package com.datayes.paas.spring;

import org.springframework.security.acls.domain.AccessControlEntryImpl;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.acls.model.Sid;
import org.springframework.util.Assert;

import java.io.Serializable;
import java.util.Date;

/**
 * Created by changhai on 13-11-5.
 */
public class TimeAccessControlEntryImpl extends AccessControlEntryImpl {
    private Permission permission;
    private boolean auditFailure = false;
    private boolean auditSuccess = false;
    private Date start;
    private Date end;

    public TimeAccessControlEntryImpl(Serializable id, Acl acl, Sid sid, Permission permission, boolean granting, boolean auditSuccess, boolean auditFailure) {
        super(id, acl, sid, permission, granting, auditSuccess, auditFailure);
        this.permission = permission;
        this.auditSuccess = auditSuccess;
        this.auditFailure = auditFailure;
    }

    public Permission getPermission() {
        return permission;
    }

    public boolean isAuditFailure() {
        return auditFailure;
    }

    public boolean isAuditSuccess() {
        return auditSuccess;
    }

    void setAuditFailure(boolean auditFailure) {
        this.auditFailure = auditFailure;
    }

    void setAuditSuccess(boolean auditSuccess) {
        this.auditSuccess = auditSuccess;
    }

    void setPermission(Permission permission) {
        Assert.notNull(permission, "Permission required");
        this.permission = permission;
    }

    public Date getEnd() {
        return end;
    }

    public void setEnd(Date end) {
        this.end = end;
    }

    public Date getStart() {
        return start;
    }

    public void setStart(Date start) {
        this.start = start;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("TimeAccessControlEntryImpl[");
        sb.append("id: ").append(this.getId()).append("; ");
        sb.append("granting: ").append(this.isGranting()).append("; ");
        sb.append("sid: ").append(this.getSid()).append("; ");
        sb.append("permission: ").append(this.getPermission()).append("; ");
        sb.append("start: ").append(this.start).append("; ");
        sb.append("end: ").append(this.end).append("; ");
        sb.append("auditSuccess: ").append(this.isAuditSuccess()).append("; ");
        sb.append("auditFailure: ").append(this.isAuditFailure());
        sb.append("]");

        return sb.toString();
    }
}
