package com.datayes.paas;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.model.*;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;

public class AclTest {
    @Test
    public void testAcl() throws Exception {
        ApplicationContext ctx = new ClassPathXmlApplicationContext(new String[]{"classpath:context/web-context.xml", "classpath:context/security-context.xml"});
        TestAcl testAcl = ctx.getBean(TestAcl.class);
        testAcl.test();
        testAcl.el("Samantha");
//        testAcl.el("haha");
        testAcl.s1();
        System.out.println(testAcl.s3());
        System.out.println(testAcl.s2());
    }
}
