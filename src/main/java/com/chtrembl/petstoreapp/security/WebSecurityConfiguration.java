package com.chtrembl.petstoreapp.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import com.chtrembl.petstoreapp.model.ContainerEnvironment;

/**
 * Wire up Spring Security
 */
@EnableWebSecurity
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {
	private static Logger logger = LoggerFactory.getLogger(WebSecurityConfiguration.class);

	@Autowired
	private AADB2COidcLoginConfigurerWrapper aadB2COidcLoginConfigurerWrapper;

	@Autowired
	private ContainerEnvironment containeEnvironment;

	@Override
	public void configure(WebSecurity web) throws Exception {
		if (this.aadB2COidcLoginConfigurerWrapper != null
				&& this.aadB2COidcLoginConfigurerWrapper.getConfigurer() != null) {
			web.ignoring().antMatchers("/content/**");
			web.ignoring().antMatchers("/.well-known/**");
		}
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {

		if (this.aadB2COidcLoginConfigurerWrapper != null
				&& this.aadB2COidcLoginConfigurerWrapper.getConfigurer() != null) {

			http.csrf().ignoringAntMatchers("/signalr/**").and()
					.authorizeRequests().anyRequest().authenticated()
					.and().apply(this.aadB2COidcLoginConfigurerWrapper.getConfigurer());

			this.containeEnvironment.setSecurityEnabled(true);
		} else {
			logger.warn(
					"azure.activedirectory.b2c.tenant, azure.activedirectory.b2c.client-id, azure.activedirectory.b2c.client-secret and azure.activedirectory.b2c.logout-success-url must be set for Azure B2C Authentication to be enabled, considering configuring Azure B2C App Registration if you would like to authenticate users.");
		}
	}
}
