package com.datayes.paas;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * Created by changhai on 13-10-28.
 */
@Controller
public class TestController {
    @Autowired
    private TestService testService;
    @RequestMapping("/test")
    @Secured("ROLE_USER")
    public void test() {
        testService.test();
    }
}
