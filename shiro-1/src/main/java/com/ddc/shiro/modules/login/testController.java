package com.ddc.shiro.modules.login;

import com.ddc.shiro.modules.user.dao.UserMapper;
import com.ddc.shiro.modules.user.dao.entity.User;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;

/**
 * @program: testshiro
 * @description:
 * @author: lw
 * @create: 2019-03-12 11:28
 **/
@RestController
public class testController {
    @Resource
    private UserMapper userMapper;
    @RequestMapping("/testUser")
    public User testUser(){
        User user = userMapper.findByUserName("admin");
        System.out.println(user.toString());
        return user;
    }
}
