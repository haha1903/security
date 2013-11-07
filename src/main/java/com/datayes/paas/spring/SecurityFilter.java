package com.datayes.paas.spring;

import org.springframework.context.ApplicationContext;
import org.springframework.core.GenericTypeResolver;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.expression.ParseException;
import org.springframework.security.access.expression.ExpressionUtils;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.FilterInvocation;
import org.springframework.web.context.support.WebApplicationContextUtils;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

/**
 * Created by changhai on 13-11-7.
 */
public class SecurityFilter extends GenericFilterBean {
    private String path = "/security";
    private SecurityExpressionHandler expressionHandler;

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;
        if ((getServletContext().getContextPath() + path).equals(request.getRequestURI())) {

            Expression accessExpression;
            try {
                accessExpression = expressionHandler.getExpressionParser().parseExpression(request.getParameter("access"));

            } catch (ParseException e) {
                IOException ioException = new IOException();
                ioException.initCause(e);
                throw ioException;
            }

            if (!ExpressionUtils.evaluateAsBoolean(accessExpression, createExpressionEvaluationContext(request, response, expressionHandler))) {
                response.sendError(403, "access denied");
            }
        } else {
            chain.doFilter(req, res);
        }
    }

    private SecurityExpressionHandler<FilterInvocation> getExpressionHandler() throws IOException {
        ApplicationContext appContext = WebApplicationContextUtils
                .getRequiredWebApplicationContext(getServletContext());
        Map<String, SecurityExpressionHandler> handlers = appContext
                .getBeansOfType(SecurityExpressionHandler.class);

        for (SecurityExpressionHandler h : handlers.values()) {
            if (FilterInvocation.class.equals(GenericTypeResolver.resolveTypeArgument(h.getClass(),
                    SecurityExpressionHandler.class))) {
                return h;
            }
        }

        throw new IOException("No visible WebSecurityExpressionHandler instance could be found in the application "
                + "context. There must be at least one in order to support expressions in JSP 'authorize' tags.");
    }

    protected EvaluationContext createExpressionEvaluationContext(HttpServletRequest request, HttpServletResponse response, SecurityExpressionHandler<FilterInvocation> handler) {
        FilterInvocation f = new FilterInvocation(request, response, new FilterChain() {
            public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
                throw new UnsupportedOperationException();
            }
        });

        return handler.createEvaluationContext(SecurityContextHolder.getContext().getAuthentication(), f);
    }

    public void setPath(String path) {
        this.path = path;
    }

    public void setExpressionHandler(SecurityExpressionHandler expressionHandler) {
        this.expressionHandler = expressionHandler;
    }
}
