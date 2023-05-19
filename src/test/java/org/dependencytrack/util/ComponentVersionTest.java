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

    @Test
    public void testParseAlpineVersion() {
        ComponentVersion version = new ComponentVersion("1.2.11-r3");

        List<String> parts = version.getVersionParts();
        Assert.assertEquals(4, parts.size());
        Assert.assertEquals("1", parts.get(0));
        Assert.assertEquals("2", parts.get(1));
        Assert.assertEquals("11", parts.get(2));
        Assert.assertEquals("r3", parts.get(3));
    }

    @Test
    public void testParseUbuntuVersion() {
        ComponentVersion version = new ComponentVersion("1:1.2.11.dfsg-2ubuntu9");

        List<String> parts = version.getVersionParts();
        Assert.assertEquals("1", parts.get(0));
        Assert.assertEquals("2", parts.get(1));
        Assert.assertEquals("11", parts.get(2));
    }

    @Test
    public void testParseUbuntu2Version() {
        ComponentVersion version = new ComponentVersion("1.5.79ubuntu1");

        List<String> parts = version.getVersionParts();
        Assert.assertEquals("1", parts.get(0));
        Assert.assertEquals("5", parts.get(1));
        Assert.assertEquals("79", parts.get(2));
    }

    @Test
    public void testParseDebianVersion() {
        ComponentVersion version = new ComponentVersion("1:1.2.11.dfsg-2+deb11u1");

        List<String> parts = version.getVersionParts();
        Assert.assertEquals("1", parts.get(0));
        Assert.assertEquals("2", parts.get(1));
        Assert.assertEquals("11", parts.get(2));
    }

    @Test
    public void testParsePlusDfsgVersion() {
        ComponentVersion version = new ComponentVersion("1.34+dfsg-1build3");

        List<String> parts = version.getVersionParts();
        Assert.assertEquals("1", parts.get(0));
        Assert.assertEquals("34", parts.get(1));
    }

    @Test
    public void testParseUbuntuGitVersion() {
        ComponentVersion version = new ComponentVersion("1:2.34.1-1ubuntu1.4");

        List<String> parts = version.getVersionParts();
        Assert.assertEquals("2", parts.get(0));
        Assert.assertEquals("34", parts.get(1));
        Assert.assertEquals("1", parts.get(2));
    }

    @Test
    public void testParseBetaPackage() {
        ComponentVersion version = new ComponentVersion("1.1.0-beta004");

        List<String> parts = version.getVersionParts();
        Assert.assertEquals("1", parts.get(0));
        Assert.assertEquals("1", parts.get(1));
        Assert.assertEquals("0", parts.get(2));
        Assert.assertEquals("beta", parts.get(3));
        Assert.assertEquals("004", parts.get(4));
    }

    @Test
    public void testParseBetaPackage2() {
        ComponentVersion version = new ComponentVersion("5.0.0-beta.2-11938");

        List<String> parts = version.getVersionParts();
        Assert.assertEquals("5", parts.get(0));
        Assert.assertEquals("0", parts.get(1));
        Assert.assertEquals("0", parts.get(2));
        Assert.assertEquals("beta", parts.get(3));
        Assert.assertEquals("2", parts.get(4));
        Assert.assertEquals("11938", parts.get(5));
    }

    @Test
    public void testParseBetaPackage3() {
        ComponentVersion version = new ComponentVersion("1.0.0-beta.1");

        List<String> parts = version.getVersionParts();
        Assert.assertEquals("1", parts.get(0));
        Assert.assertEquals("0", parts.get(1));
        Assert.assertEquals("0", parts.get(2));
        Assert.assertEquals("beta", parts.get(3));
        Assert.assertEquals("1", parts.get(4));
    }

    @Test
    public void testParsePreviewPackage() {
        ComponentVersion version = new ComponentVersion("1.0.0-preview4");

        List<String> parts = version.getVersionParts();
        Assert.assertEquals("1", parts.get(0));
        Assert.assertEquals("0", parts.get(1));
        Assert.assertEquals("0", parts.get(2));
        Assert.assertEquals("preview", parts.get(3));
        Assert.assertEquals("4", parts.get(4));
    }

    @Test
    public void testParseColonPackage() {
        ComponentVersion version = new ComponentVersion("1:5.39-3");

        List<String> parts = version.getVersionParts();
        Assert.assertEquals("5", parts.get(0));
        Assert.assertEquals("39", parts.get(1));
    }

}
