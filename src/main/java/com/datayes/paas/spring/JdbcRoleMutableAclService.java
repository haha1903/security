package com.datayes.paas.spring;

import org.springframework.jdbc.core.RowCallbackHandler;
import org.springframework.security.acls.jdbc.JdbcMutableAclService;
import org.springframework.security.acls.jdbc.LookupStrategy;
import org.springframework.security.acls.model.AclCache;
import org.springframework.security.acls.model.Sid;

import javax.sql.DataSource;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by changhai on 13-11-5.
 */
public class JdbcRoleMutableAclService extends JdbcMutableAclService implements RoleMutableAclService {
    private String updateSidhigher = "update acl_sid set higher = ? where id = ? and principal = 0";
    private String selecthigherChildSid = "select p.sid higher_sid, c.sid from acl_sid p join acl_sid c on(p.id = c.higher)";
    private RoleHierarchyImpl roleHierarchy;

    public JdbcRoleMutableAclService(DataSource dataSource, LookupStrategy lookupStrategy, AclCache aclCache) {
        super(dataSource, lookupStrategy, aclCache);
    }

    @Override
    public Long createOrRetrieveSidPrimaryKey(Sid sid) {
        return super.createOrRetrieveSidPrimaryKey(sid, true);
    }

    public void includeRole(long higherRoleId, long lowerRoleId) {
        int updated = jdbcTemplate.update(updateSidhigher, higherRoleId, lowerRoleId);
        if (updated > 0) {
            final Map<String, String> roleHierarchyMapRepresentation = new HashMap<String, String>();
            jdbcTemplate.query(selecthigherChildSid, new RowCallbackHandler() {
                @Override
                public void processRow(ResultSet rs) throws SQLException {
                    roleHierarchyMapRepresentation.put(rs.getString("higher_sid"), rs.getString("sid"));
                }
            });
            roleHierarchy.setHierarchy(roleHierarchyMapRepresentation);
        }
    }

    public void setRoleHierarchy(RoleHierarchyImpl roleHierarchy) {
        this.roleHierarchy = roleHierarchy;
    }
}
