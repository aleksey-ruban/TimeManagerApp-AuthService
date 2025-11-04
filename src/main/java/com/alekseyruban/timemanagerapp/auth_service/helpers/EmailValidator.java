package com.alekseyruban.timemanagerapp.auth_service.helpers;

import org.springframework.stereotype.Service;

import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.util.Hashtable;
import java.util.regex.Pattern;

@Service
public class EmailValidator {

    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$"
    );

    private boolean isValidFormat(String email) {
        return EMAIL_PATTERN.matcher(email).matches();
    }

    private boolean isDomainValid(String email) {
        String domain = email.substring(email.indexOf("@") + 1);
        try {
            Hashtable<String, String> env = new Hashtable<>();
            env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
            DirContext ctx = new InitialDirContext(env);
            Attributes attrs = ctx.getAttributes(domain, new String[]{"MX"});
            if (attrs != null && attrs.get("MX") != null) {
                return true;
            }
            attrs = ctx.getAttributes(domain, new String[]{"A"});
            return attrs != null && attrs.get("A") != null;
        } catch (NamingException e) {
            return false;
        }
    }

    public boolean isEmailPotentiallyValid(String email) {
        return isValidFormat(email) && isDomainValid(email);
    }
}