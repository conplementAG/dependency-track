package org.dependencytrack.util;

import org.junit.Assert;
import org.junit.Test;

import java.util.List;

public class ComponentVersionTest {
    @Test
    public void testParseSimpleOpenSslVersion() {
        ComponentVersion version = new ComponentVersion("1.1.1j");

        List<String> parts = version.getVersionParts();
        Assert.assertEquals(3, parts.size());
        Assert.assertEquals("1", parts.get(0));
        Assert.assertEquals("1", parts.get(1));
        Assert.assertEquals("1j", parts.get(2));
    }
}
