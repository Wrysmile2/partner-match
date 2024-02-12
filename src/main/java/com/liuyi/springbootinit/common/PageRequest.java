package com.liuyi.springbootinit.common;

import lombok.Data;

import java.io.Serializable;

/**
 * 分页请求
 */
@Data
public class PageRequest implements Serializable {
    private static final long serialVersionUID = -7310366548235104148L;
    /**
     * 页面大小
     */
    private int pageSize = 10;

    /**
     * 当前是第几页
     */
    private int pageNum = 1;
}
