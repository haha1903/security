package com.datayes.paas.spring.time;

import com.datayes.paas.spring.JdbcRoleMutableAclService;
import org.springframework.jdbc.core.BatchPreparedStatementSetter;
import org.springframework.security.acls.domain.AccessControlEntryImpl;
import org.springframework.security.acls.jdbc.LookupStrategy;
import org.springframework.security.acls.model.AccessControlEntry;
import org.springframework.security.acls.model.AclCache;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.util.Assert;

import javax.sql.DataSource;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;

/**
 * Created by changhai on 13-11-5.
 */
public class TimeJdbcRoleMutableAclService extends JdbcRoleMutableAclService {
    private String insertEntry = "insert into acl_entry "
            + "(acl_object_identity, ace_order, sid, mask, granting, audit_success, audit_failure, start, end)"
            + "values (?, ?, ?, ?, ?, ?, ?, ?, ?)";

    public TimeJdbcRoleMutableAclService(DataSource dataSource, LookupStrategy lookupStrategy, AclCache aclCache) {
        super(dataSource, lookupStrategy, aclCache);
    }

    protected void createEntries(final MutableAcl acl) {
        jdbcTemplate.batchUpdate(insertEntry,
                new BatchPreparedStatementSetter() {
                    public int getBatchSize() {
                        return acl.getEntries().size();
                    }

                    public void setValues(PreparedStatement stmt, int i) throws SQLException {
                        AccessControlEntry entry_ = acl.getEntries().get(i);
                        Assert.isTrue(entry_ instanceof AccessControlEntryImpl, "Unknown ACE class");
                        AccessControlEntryImpl entry = (AccessControlEntryImpl) entry_;

                        stmt.setLong(1, ((Long) acl.getId()).longValue());
                        stmt.setInt(2, i);
                        stmt.setLong(3, createOrRetrieveSidPrimaryKey(entry.getSid(), true).longValue());
                        stmt.setInt(4, entry.getPermission().getMask());
                        stmt.setBoolean(5, entry.isGranting());
                        stmt.setBoolean(6, entry.isAuditSuccess());
                        stmt.setBoolean(7, entry.isAuditFailure());
                        Timestamp start = null;
                        Timestamp end = null;
                        if (entry instanceof TimeAccessControlEntryImpl) {
                            TimeAccessControlEntryImpl timeAccessControlEntry = (TimeAccessControlEntryImpl) entry;
                            start = new Timestamp(timeAccessControlEntry.getStart().getTime());
                            end = new Timestamp(timeAccessControlEntry.getEnd().getTime());
                        }
                        stmt.setTimestamp(8, start);
                        stmt.setTimestamp(9, end);
                    }
                });
    }
}
