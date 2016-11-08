package org.cloudfoundry.identity.uaa.authentication;

import org.springframework.security.authentication.BadCredentialsException;

public class PasswordForcedChangeException extends BadCredentialsException {
    public PasswordForcedChangeException(String msg) {
        super(msg);
    }
}
