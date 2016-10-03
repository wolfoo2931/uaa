package org.cloudfoundry.identity.uaa.authentication.listener;

import org.cloudfoundry.identity.uaa.authentication.event.UserAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.login.SavedAccountOption;
import org.cloudfoundry.identity.uaa.security.LoginReferenceSavingFilter;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.springframework.context.ApplicationListener;
import org.springframework.web.context.ServletContextAware;

import javax.servlet.ServletContext;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
public class UserAuthenticationSuccessListener implements ApplicationListener<UserAuthenticationSuccessEvent>, ServletContextAware {

    private final ScimUserProvisioning scimUserProvisioning;
    private ServletContext servletContext;

    public UserAuthenticationSuccessListener(ScimUserProvisioning scimUserProvisioning) {
        this.scimUserProvisioning = scimUserProvisioning;
    }

    @Override
    public void onApplicationEvent(UserAuthenticationSuccessEvent event) {
        UaaUser user = event.getUser();
        if(user.isLegacyVerificationBehavior() && !user.isVerified()) {
            scimUserProvisioning.verifyUser(user.getId(), -1);
        }

        HttpServletRequest loginRequest = LoginReferenceSavingFilter.getSavedRequest().get();

        if(loginRequest != null) {
            SavedAccountOption savedAccountOption = new SavedAccountOption();
            savedAccountOption.setEmail(user.getEmail());
            savedAccountOption.setOrigin(user.getOrigin());
            savedAccountOption.setUserId(user.getId());
            savedAccountOption.setUsername(user.getUsername());
            Cookie cookie = new Cookie("Saved-Account-" + user.getId(), JsonUtils.writeValueAsString(savedAccountOption));

            cookie.setPath(servletContext.getContextPath() + "/login");
            cookie.setHttpOnly(true);
            cookie.setSecure(loginRequest.isSecure());
            // cookie expires in a year
            cookie.setMaxAge(365*24*60*60);

            HttpServletResponse loginResponse = LoginReferenceSavingFilter.getSavedResponse().get();
            loginResponse.addCookie(cookie);
        }
    }

    @Override
    public void setServletContext(ServletContext servletContext) {
        this.servletContext = servletContext;
    }
}
