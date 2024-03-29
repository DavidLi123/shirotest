package com.ddc.shiro.modules.user.dao;

import com.ddc.shiro.modules.user.dao.entity.Role;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.Set;

/**
 * @author: WangSaiChao
 * @date: 2018/5/12
 * @description: 角色操作dao层
 */
@Mapper
public interface RoleMapper {

    /**
     * 根据用户id查询角色信息
     * @param uid
     * @return
     */
    Set<Role> findRolesByUserId(@Param("uid") Integer uid);
}
