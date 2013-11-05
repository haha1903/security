package com.datayes.paas;

import org.junit.Test;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;

/**
 * Created by changhai on 13-11-4.
 */
public class RoleHierarchyTest {
    @Test
    public void testRoleHierarchy() throws Exception {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy("1 > 2\n1 > 3\n1 > 4\n4 > 1");

    }
}
