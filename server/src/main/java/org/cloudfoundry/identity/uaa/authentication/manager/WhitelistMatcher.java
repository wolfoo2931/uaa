package org.cloudfoundry.identity.uaa.authentication.manager;

import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class WhitelistMatcher {

    public static LinkedList<String> filterAuthorities(List<String> externalWhiteList, Set<String> authorities) {
        Pattern pattern;

        Set<String> filteredAuthorities = new HashSet<>();

        for(String groupWhiteList: externalWhiteList){
            pattern = Pattern.compile(groupWhiteList);
            for(String authority : authorities){
                Matcher matcher = pattern.matcher(authority);
                if (matcher.find()) {
                    filteredAuthorities.add(authority);
                }
            }
        }


        return new LinkedList<String>(filteredAuthorities);
    }
}
