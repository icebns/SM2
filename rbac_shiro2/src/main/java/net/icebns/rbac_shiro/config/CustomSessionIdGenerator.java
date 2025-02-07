package net.icebns.rbac_shiro.config;

import org.apache.shiro.session.Session;
import org.apache.shiro.session.mgt.eis.SessionIdGenerator;

import java.io.Serializable;
import java.util.UUID;

/**
 * 自定义sesionid生成
 */
public class CustomSessionIdGenerator implements SessionIdGenerator {

    @Override
    public Serializable generateId(Session session) {

        return "icebns"+UUID.randomUUID().toString().replace("-","");

    }


}
