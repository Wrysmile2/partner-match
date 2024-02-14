package com.yjw.springbootinit.constant;

/**
 * 用户常量
 */
public interface UserConstant {

    /**
     * 用户登录态键值
     */
    String LOGIN_USER_STATUS = "loginUserStatus";

    //  region 权限

    /**
     * 默认角色
     */
    String DEFAULT_ROLE = "user";

    /**
     * 管理员角色
     */
    String ADMIN_ROLE = "admin";

    /**
     * 被封号
     */
    String BAN_ROLE = "ban";

    // endregion
}
