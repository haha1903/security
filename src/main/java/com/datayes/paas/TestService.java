package com.datayes.paas;

import org.springframework.security.access.annotation.Secured;

/**
 * Created by changhai on 13-10-28.
 */
public interface TestService {
    @Secured("ROLE_USER")
    void test();
}
