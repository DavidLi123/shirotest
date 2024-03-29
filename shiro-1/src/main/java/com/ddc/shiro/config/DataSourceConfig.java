package com.ddc.shiro.config;

import com.alibaba.druid.pool.DruidDataSource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.sql.DataSource;
import java.sql.SQLException;

/**
 * @program: testshiro
 * @description:
 * @author: lw
 * @create: 2019-03-11 17:28
 **/
@Configuration
public class DataSourceConfig {
    /**
     * 数据源驱动类型
     */
    @Value("${jdbc.ds.driverClassName}")
    private String driver;

    /**
     * 连接地址
     */
    @Value("${jdbc.ds.url}")
    private String url;

    /**
     * 用户名
     */
    @Value("${jdbc.ds.username}")
    private String username;

    /**
     * 密码
     */
    @Value("${jdbc.ds.password}")
    private String password;

    /**
     * 配置Druid数据源
     */
    @Bean(name="dataSource", destroyMethod = "close", initMethod = "init")
    public DataSource dataSource() throws SQLException{
        DruidDataSource dataSource = new DruidDataSource();
        dataSource.setDriverClassName(driver);
        dataSource.setUrl(url);
        dataSource.setUsername(username);
        dataSource.setPassword(password);
        //配置最大连接
        dataSource.setMaxActive(20);
        //配置初始连接
        dataSource.setInitialSize(5);
        //配置最小连接
        dataSource.setMinIdle(20);
        //连接等待超时时间
        dataSource.setMaxWait(60000);
        //间隔多久进行检测,关闭空闲连接
        dataSource.setTimeBetweenEvictionRunsMillis(60000);
        //一个连接最小生存时间
        dataSource.setMinEvictableIdleTimeMillis(300000);
        //连接等待超时时间 单位为毫秒 缺省启用公平锁，
        //并发效率会有所下降， 如果需要可以通过配置useUnfairLock属性为true使用非公平锁
        dataSource.setUseUnfairLock(true);
        //用来检测是否有效的sql
        dataSource.setValidationQuery("select 'x'");
        dataSource.setTestWhileIdle(true);
        //申请连接时执行validationQuery检测连接是否有效，配置为true会降低性能
        dataSource.setTestOnBorrow(false);
        //归还连接时执行validationQuery检测连接是否有效，配置为true会降低性能
        dataSource.setTestOnReturn(false);
        return dataSource;
    }
}
