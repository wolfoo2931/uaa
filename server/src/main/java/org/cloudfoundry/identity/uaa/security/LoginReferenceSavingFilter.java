/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.security;

import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class LoginReferenceSavingFilter extends OncePerRequestFilter {

    private static ThreadLocal<HttpServletRequest> savedRequest = new ThreadLocal<>();
    public static ThreadLocal<HttpServletRequest> getSavedRequest() {
        return savedRequest;
    }

    private static ThreadLocal<HttpServletResponse> savedResponse = new ThreadLocal<>();
    public static ThreadLocal<HttpServletResponse> getSavedResponse() {
        return savedResponse;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        savedRequest.set(request);
        savedResponse.set(response);
        filterChain.doFilter(request, response);
    }
}
