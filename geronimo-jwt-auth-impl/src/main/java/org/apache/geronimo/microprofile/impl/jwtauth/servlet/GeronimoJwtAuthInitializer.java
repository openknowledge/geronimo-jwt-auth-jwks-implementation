/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.geronimo.microprofile.impl.jwtauth.servlet;

import static java.util.Optional.ofNullable;

import java.util.Comparator;
import java.util.EnumSet;
import java.util.Set;

import javax.servlet.DispatcherType;
import javax.servlet.FilterRegistration;
import javax.servlet.ServletContainerInitializer;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.annotation.HandlesTypes;
import javax.ws.rs.core.Application;

import org.apache.geronimo.microprofile.impl.jwtauth.config.GeronimoJwtAuthConfig;
import org.eclipse.microprofile.auth.LoginConfig;

@HandlesTypes(LoginConfig.class)
public class GeronimoJwtAuthInitializer implements ServletContainerInitializer {
    @Override
    public void onStartup(final Set<Class<?>> classes, final ServletContext ctx) throws ServletException {
        final GeronimoJwtAuthConfig appConfig = GeronimoJwtAuthConfig.create();

        ofNullable(classes).filter(c -> !c.isEmpty()).ifPresent(marked -> marked.stream()
                .filter(Application.class::isAssignableFrom) // needed?
                .map(it -> it.getAnnotation(LoginConfig.class))
                .filter(it -> "MP-JWT".equalsIgnoreCase(it.authMethod()))
                .sorted(Comparator.comparing(LoginConfig::realmName)) // to be deterministic
                .findFirst()
                .ifPresent(config -> {
                    final FilterRegistration.Dynamic filter = ctx.addFilter("geronimo-microprofile-jwt-auth-filter", GeronimoJwtAuthFilter.class);
                    filter.setAsyncSupported(true);
                    filter.addMappingForUrlPatterns(EnumSet.allOf(DispatcherType.class), false, appConfig.read("geronimo.jwt-auth.servlet.filter.mapping", "/*"));
                }));
    }
}
