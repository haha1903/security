package com.datayes.paas.spring;


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.access.hierarchicalroles.CycleInRoleHierarchyException;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.*;

public class RoleHierarchyImpl implements RoleHierarchy {

    private static final Log logger = LogFactory.getLog(RoleHierarchyImpl.class);

    /**
     * rolesReachableInOneStepMap is a Map that under the key of a specific role name contains a set of all roles
     * reachable from this role in 1 step
     */
    private Map<GrantedAuthority, Set<GrantedAuthority>> rolesReachableInOneStepMap = null;

    /**
     * rolesReachableInOneOrMoreStepsMap is a Map that under the key of a specific role name contains a set of all
     * roles reachable from this role in 1 or more steps
     */
    private Map<GrantedAuthority, Set<GrantedAuthority>> rolesReachableInOneOrMoreStepsMap = null;
    private Map<String, String> roleHierarchyMapRepresentation;

    /**
     * Set the role hierarchy and pre-calculate for every role the set of all reachable roles, i.e. all roles lower in
     * the hierarchy of every given role. Pre-calculation is done for performance reasons (reachable roles can then be
     * calculated in O(1) time).
     * During pre-calculation, cycles in role hierarchy are detected and will cause a
     * <tt>CycleInRoleHierarchyException</tt> to be thrown.
     *
     * @param roleHierarchyMapRepresentation - String definition of the role hierarchy.
     */
    public void setHierarchy(Map<String, String> roleHierarchyMapRepresentation) {
        this.roleHierarchyMapRepresentation = roleHierarchyMapRepresentation;

        logger.debug("setHierarchy() - The following role hierarchy was set: " + roleHierarchyMapRepresentation);

        buildRolesReachableInOneStepMap();
        buildRolesReachableInOneOrMoreStepsMap();
    }

    public Collection<GrantedAuthority> getReachableGrantedAuthorities(Collection<? extends GrantedAuthority> authorities) {
        if (authorities == null || authorities.isEmpty()) {
            return AuthorityUtils.NO_AUTHORITIES;
        }

        Set<GrantedAuthority> reachableRoles = new HashSet<GrantedAuthority>();

        for (GrantedAuthority authority : authorities) {
            addReachableRoles(reachableRoles, authority);
            Set<GrantedAuthority> additionalReachableRoles = getRolesReachableInOneOrMoreSteps(authority);
            if (additionalReachableRoles != null) {
                reachableRoles.addAll(additionalReachableRoles);
            }
        }

        if (logger.isDebugEnabled()) {
            logger.debug("getReachableGrantedAuthorities() - From the roles " + authorities
                    + " one can reach " + reachableRoles + " in zero or more steps.");
        }

        List<GrantedAuthority> reachableRoleList = new ArrayList<GrantedAuthority>(reachableRoles.size());
        reachableRoleList.addAll(reachableRoles);

        return reachableRoleList;
    }

    // SEC-863
    private void addReachableRoles(Set<GrantedAuthority> reachableRoles,
                                   GrantedAuthority authority) {

        for (GrantedAuthority testAuthority : reachableRoles) {
            String testKey = testAuthority.getAuthority();
            if ((testKey != null) && (testKey.equals(authority.getAuthority()))) {
                return;
            }
        }
        reachableRoles.add(authority);
    }

    // SEC-863
    private Set<GrantedAuthority> getRolesReachableInOneOrMoreSteps(
            GrantedAuthority authority) {

        if (authority.getAuthority() == null) {
            return null;
        }

        for (GrantedAuthority testAuthority : rolesReachableInOneOrMoreStepsMap.keySet()) {
            String testKey = testAuthority.getAuthority();
            if ((testKey != null) && (testKey.equals(authority.getAuthority()))) {
                return rolesReachableInOneOrMoreStepsMap.get(testAuthority);
            }
        }

        return null;
    }

    /**
     * Parse input and build the map for the roles reachable in one step: the higher role will become a key that
     * references a set of the reachable lower roles.
     */
    private void buildRolesReachableInOneStepMap() {

        rolesReachableInOneStepMap = new HashMap<GrantedAuthority, Set<GrantedAuthority>>();

        for (Map.Entry<String, String> entry : roleHierarchyMapRepresentation.entrySet()) {
            GrantedAuthority higherRole = new SimpleGrantedAuthority(entry.getKey());
            GrantedAuthority lowerRole = new SimpleGrantedAuthority(entry.getValue());
            Set<GrantedAuthority> rolesReachableInOneStepSet;

            if (!rolesReachableInOneStepMap.containsKey(higherRole)) {
                rolesReachableInOneStepSet = new HashSet<GrantedAuthority>();
                rolesReachableInOneStepMap.put(higherRole, rolesReachableInOneStepSet);
            } else {
                rolesReachableInOneStepSet = rolesReachableInOneStepMap.get(higherRole);
            }
            addReachableRoles(rolesReachableInOneStepSet, lowerRole);

            logger.debug("buildRolesReachableInOneStepMap() - From role "
                    + higherRole + " one can reach role " + lowerRole + " in one step.");
        }
    }

    /**
     * For every higher role from rolesReachableInOneStepMap store all roles that are reachable from it in the map of
     * roles reachable in one or more steps. (Or throw a CycleInRoleHierarchyException if a cycle in the role
     * hierarchy definition is detected)
     */
    private void buildRolesReachableInOneOrMoreStepsMap() {
        rolesReachableInOneOrMoreStepsMap = new HashMap<GrantedAuthority, Set<GrantedAuthority>>();
        // iterate over all higher roles from rolesReachableInOneStepMap

        for (GrantedAuthority role : rolesReachableInOneStepMap.keySet()) {
            Set<GrantedAuthority> rolesToVisitSet = new HashSet<GrantedAuthority>();

            if (rolesReachableInOneStepMap.containsKey(role)) {
                rolesToVisitSet.addAll(rolesReachableInOneStepMap.get(role));
            }

            Set<GrantedAuthority> visitedRolesSet = new HashSet<GrantedAuthority>();

            while (!rolesToVisitSet.isEmpty()) {
                // take a role from the rolesToVisit set
                GrantedAuthority aRole = rolesToVisitSet.iterator().next();
                rolesToVisitSet.remove(aRole);
                addReachableRoles(visitedRolesSet, aRole);
                if (rolesReachableInOneStepMap.containsKey(aRole)) {
                    Set<GrantedAuthority> newReachableRoles = rolesReachableInOneStepMap.get(aRole);

                    // definition of a cycle: you can reach the role you are starting from
                    if (rolesToVisitSet.contains(role) || visitedRolesSet.contains(role)) {
                        throw new CycleInRoleHierarchyException();
                    } else {
                        // no cycle
                        rolesToVisitSet.addAll(newReachableRoles);
                    }
                }
            }
            rolesReachableInOneOrMoreStepsMap.put(role, visitedRolesSet);

            logger.debug("buildRolesReachableInOneOrMoreStepsMap() - From role "
                    + role + " one can reach " + visitedRolesSet + " in one or more steps.");
        }

    }

}
