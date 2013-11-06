package com.datayes.paas.spring;

import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.RowCallbackHandler;
import org.springframework.security.acls.jdbc.JdbcMutableAclService;
import org.springframework.security.acls.jdbc.LookupStrategy;
import org.springframework.security.acls.model.AclCache;
import org.springframework.security.acls.model.Sid;

import javax.annotation.PostConstruct;
import javax.sql.DataSource;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by changhai on 13-11-5.
 */
public class JdbcRoleMutableAclService extends JdbcMutableAclService implements RoleMutableAclService {
    private String insertSidInclude = "insert into acl_sid_include(higher, lower) values(?, ?)";
    private String removeSidInclude = "delete from acl_sid_include where higher = ? and lower = ?";
    private String selectSidInclude = "select higher.sid higher_sid, lower.sid lower_sid from acl_sid_include i join acl_sid higher on (i.higher = higher.id) join acl_sid lower on (i.lower = lower.id)";
    private RoleHierarchyImpl roleHierarchy;

    public JdbcRoleMutableAclService(DataSource dataSource, LookupStrategy lookupStrategy, AclCache aclCache) {
        super(dataSource, lookupStrategy, aclCache);
    }

    @Override
    public Long createOrRetrieveSidPrimaryKey(Sid sid) {
        return super.createOrRetrieveSidPrimaryKey(sid, true);
    }

    public void includeRole(long higherRoleId, long lowerRoleId) {
        try {
            jdbcTemplate.update(insertSidInclude, higherRoleId, lowerRoleId);
            initRole();
        } catch (DuplicateKeyException e) {
            // ignores
        }
    }

    public void removeIncludeRole(long higherRoleId, long lowerRoleId) {
        int updated = jdbcTemplate.update(removeSidInclude, higherRoleId, lowerRoleId);
        if (updated > 0) {
            initRole();
        }
    }

    @PostConstruct
    private void initRole() {
        final Map<String, String> roleHierarchyMapRepresentation = new HashMap<String, String>();
        jdbcTemplate.query(selectSidInclude, new RowCallbackHandler() {
            @Override
            public void processRow(ResultSet rs) throws SQLException {
                roleHierarchyMapRepresentation.put(rs.getString("higher_sid"), rs.getString("lower_sid"));
            }
        });
        roleHierarchy.setHierarchy(roleHierarchyMapRepresentation);
    }

    public void setRoleHierarchy(RoleHierarchyImpl roleHierarchy) {
        this.roleHierarchy = roleHierarchy;
    }
}
