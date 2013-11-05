package com.datayes.paas;

import com.datayes.paas.spring.RoleMutableAclService;
import com.datayes.paas.spring.time.TimeAcl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.domain.GrantedAuthoritySid;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.model.*;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Date;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by changhai on 13-10-29.
 */
@Service
public class TestAcl {
    @Autowired
    private RoleMutableAclService aclService;

    @Secured("ROLE_USER")
    public void s1() {
        System.out.println("s1");
    }

    @Secured({"AFTER_ACL_READ", "ROLE_USER"})
    public Foo s2() {
        Foo foo = new Foo();
        foo.setId(1);
        foo.setType(2);
        foo.setValue(3);
        return foo;
    }

    @PreAuthorize("#name==principal and hasRole('ROLE_USER')")
    public void el(String name) {
        System.out.println(name);
    }

    @Secured({"AFTER_ACL_COLLECTION_READ", "ROLE_USER"})
    public List<Foo> s3() {
        ArrayList<Foo> foos = new ArrayList<Foo>();
        Foo foo = new Foo();
        foo.setId(1);
        foo.setType(2);
        foo.setValue(3);
        foos.add(foo);
        foo = new Foo();
        foo.setId(2);
        foo.setType(2);
        foo.setValue(3);
        foos.add(foo);
        foo = new Foo();
        foo.setId(3);
        foo.setType(4);
        foo.setValue(3);
        foos.add(foo);
        return foos;
    }

    @Transactional
    public void test() {
        Long roleAdminId = aclService.createOrRetrieveSidPrimaryKey(new GrantedAuthoritySid("ROLE_ADMIN"));
        Long roleUserId = aclService.createOrRetrieveSidPrimaryKey(new GrantedAuthoritySid("ROLE_USER"));
        aclService.includeRole(roleAdminId, roleUserId);
        // Prepare the information we'd like in our access control entry (ACE)
        ObjectIdentity oi = new ObjectIdentityImpl(Foo.class, 1);
        ObjectIdentity oi2 = new ObjectIdentityImpl(Foo.class, 2);
        Sid sid = new PrincipalSid("Samantha");
        Permission p = BasePermission.READ;

        // Create or update the relevant ACL
        ArrayList<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        authorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken("Samantha", "123456", authorities);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        TimeAcl acl = null;
        MutableAcl acl2 = null;
        try {
            acl = (TimeAcl) aclService.readAclById(oi);
            acl2 = (MutableAcl) aclService.readAclById(oi2);
        } catch (NotFoundException nfe) {
            acl = (TimeAcl) aclService.createAcl(oi);
            acl2 = aclService.createAcl(oi2);
            acl2.setParent(acl);
            aclService.updateAcl(acl2);
        }
        ObjectIdentity oi3 = new ObjectIdentityImpl(FooType.class, 2);
        MutableAcl acl3 = aclService.createAcl(oi3);
//        acl3.insertAce(acl3.getEntries().size(), p, sid, true);
//        aclService.updateAcl(acl3);

        // Now grant some permissions via an access control entry (ACE)
        // Time Permission
        Date start = new Date(System.currentTimeMillis() - 10000);
        Date end = new Date(System.currentTimeMillis() + 10000);
        acl.insertAce(acl.getEntries().size(), p, sid, true, start, end);
//        acl2.insertAce(acl2.getEntries().size(), p, sid, true);
        aclService.updateAcl(acl);
//        aclService.updateAcl(acl2);
        System.out.println("update success");
    }
}
