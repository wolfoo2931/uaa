package org.cloudfoundry.identity.uaa.authentication.manager;

import com.google.common.collect.Sets;
import org.junit.Test;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class WhitelistMatcherTest {
    @Test
    public void testFilterAuthorities() {
        List<String> whitelist = Arrays.asList("whitelisted-group");
        Set<String> authorities = Sets.newHashSet("whitelisted-group", "other-thing");
        LinkedList<String> externalUserAuthorities = WhitelistMatcher.filterAuthorities(whitelist, authorities);

        assertEquals(1, externalUserAuthorities.size());
        assertEquals("whitelisted-group", externalUserAuthorities.get(0));
    }

    @Test
    public void testFilterAuthorities_withWildcard() {
        List<String> whitelist = Arrays.asList("whitelisted-.*");
        Set<String> authorities = Sets.newHashSet("whitelisted-group",
                                                  "whitelisted-other-thing",
                                                  "whitelisted-cat",
                                                  "not-whitelisted");
        LinkedList<String> externalUserAuthorities = WhitelistMatcher.filterAuthorities(whitelist, authorities);

        assertEquals(3, externalUserAuthorities.size());
        assertTrue(externalUserAuthorities.contains("whitelisted-group"));
        assertTrue(externalUserAuthorities.contains("whitelisted-other-thing"));
        assertTrue(externalUserAuthorities.contains("whitelisted-cat"));
        assertFalse(externalUserAuthorities.contains("not-whitelisted"));
    }

    @Test
    public void testFilterAuthorities_withWildcardInMultiplePatterns() {
        List<String> whitelist = Arrays.asList("^admin-.*", "security-*");
        Set<String> authorities = Sets.newHashSet("admin-hr",
                                                  "nonadmin",
                                                  "security-eng",
                                                  "security-directors",
                                                  "support-billing");
        LinkedList<String> externalUserAuthorities = WhitelistMatcher.filterAuthorities(whitelist, authorities);

        assertEquals(3, externalUserAuthorities.size());
        assertTrue(externalUserAuthorities.contains("admin-hr"));
        assertTrue(externalUserAuthorities.contains("security-eng"));
        assertTrue(externalUserAuthorities.contains("security-directors"));
        assertFalse(externalUserAuthorities.contains("nonadmin"));
        assertFalse(externalUserAuthorities.contains("support-billing"));
    }
}
