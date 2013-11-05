package com.datayes.paas;

import org.springframework.security.access.annotation.Secured;
import org.springframework.stereotype.Service;

/**
 * Created by changhai on 13-10-28.
 */
@Service
public class TestServiceImpl implements TestService {
    @Override
    @Secured("ROLE_TEST")
    public void test() {
        System.out.println("test service");
    }
}
