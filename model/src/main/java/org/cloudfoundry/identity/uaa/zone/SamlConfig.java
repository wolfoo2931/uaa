/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.zone;

import java.util.HashMap;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.cloudfoundry.identity.uaa.saml.SamlKey;

import static org.springframework.util.StringUtils.hasText;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class SamlConfig {
    public static final String LEGACY_KEY_ID = "legacy-saml-key";

    private boolean assertionSigned = true;
    private boolean requestSigned = true;
    private boolean wantAssertionSigned = true;
    private boolean wantAuthnRequestSigned = false;
    private int assertionTimeToLiveSeconds = 600;
    @JsonIgnore
    private String certificate;
    @JsonIgnore
    private String privateKey;
    @JsonIgnore
    private String privateKeyPassword;

    private String activeKeyId;
    private Map<String, SamlKey> keys = new HashMap<>();

    public boolean isAssertionSigned() {
        return assertionSigned;
    }

    public void setAssertionSigned(boolean assertionSigned) {
        this.assertionSigned = assertionSigned;
    }

    public boolean isRequestSigned() {
        return requestSigned;
    }

    public void setRequestSigned(boolean requestSigned) {
        this.requestSigned = requestSigned;
    }

    public boolean isWantAssertionSigned() {
        return wantAssertionSigned;
    }

    public void setWantAssertionSigned(boolean wantAssertionSigned) {
        this.wantAssertionSigned = wantAssertionSigned;
    }

    @JsonProperty("certificate")
    public void setCertificate(String certificate) {
        this.certificate = certificate;
    }

    @JsonProperty("privateKey")
    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }

    @JsonProperty("privateKeyPassword")
    public void setPrivateKeyPassword(String privateKeyPassword) {
        this.privateKeyPassword = privateKeyPassword;
    }

    public boolean isWantAuthnRequestSigned() {
        return wantAuthnRequestSigned;
    }

    public void setWantAuthnRequestSigned(boolean wantAuthnRequestSigned) {
        this.wantAuthnRequestSigned = wantAuthnRequestSigned;
    }

    public int getAssertionTimeToLiveSeconds() {
        return assertionTimeToLiveSeconds;
    }

    public void setAssertionTimeToLiveSeconds(int assertionTimeToLiveSeconds) {
        this.assertionTimeToLiveSeconds = assertionTimeToLiveSeconds;
    }

    @JsonIgnore
    public String getCertificate() {
        if (hasLegacyKey()) {
            return certificate;
        } else {
            SamlKey legacyKey = keys.get(LEGACY_KEY_ID);
            if (null != legacyKey) {
                return legacyKey.getCertificate();
            }
        }
        return null;
    }

    @JsonIgnore
    public String getPrivateKey() {
        if (hasLegacyKey()) {
            return privateKey;
        } else {
            SamlKey legacyKey = keys.get(LEGACY_KEY_ID);
            if (null != legacyKey) {
                return legacyKey.getKey();
            }
        }
        return null;
    }

    @JsonIgnore
    public String getPrivateKeyPassword() {
        if (hasLegacyKey()) {
            return privateKeyPassword;
        } else {
            SamlKey legacyKey = keys.get(LEGACY_KEY_ID);
            if (null != legacyKey) {
                return legacyKey.getPassphrase();
            }
        }
        return null;
    }

    public String getActiveKeyId() {
        return activeKeyId;
    }

    public void setActiveKeyId(String activeKeyId) {
        this.activeKeyId = activeKeyId;
    }

    public Map<String, SamlKey> getKeys() {
        if (hasLegacyKey()) {
            SamlKey key = new SamlKey(privateKey, privateKeyPassword, certificate);
            keys.put(LEGACY_KEY_ID, key);
        }
        return keys;
    }

    public void setKeys(Map<String, SamlKey> keys) {
        this.keys = keys;
    }

    @JsonIgnore
    public void addActiveKey(String keyId, SamlKey key) {
        addKey(keyId, key);
        this.activeKeyId = keyId;
    }

    @JsonIgnore
    public void addKey(String keyId, SamlKey key) {
        keys.put(keyId, key);
    }

    @JsonIgnore
    protected boolean hasLegacyKey() {
        return hasText(privateKey) && hasText(certificate);
    }
}
