package com.datayes.paas.spring;

import org.springframework.security.acls.model.MutableAclService;
import org.springframework.security.acls.model.Sid;

/**
 * Created by changhai on 13-11-5.
 */
public interface RoleMutableAclService extends MutableAclService {
    Long createOrRetrieveSidPrimaryKey(Sid sid);

    void includeRole(long higherRoleId, long lowerRoleId);
}
