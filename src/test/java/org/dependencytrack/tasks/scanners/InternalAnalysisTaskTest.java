package org.dependencytrack.tasks.scanners;

import alpine.persistence.PaginatedResult;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.parser.nvd.ModelConverter;
import org.junit.Test;
import us.springett.parsers.cpe.exceptions.CpeEncodingException;
import us.springett.parsers.cpe.exceptions.CpeParsingException;

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class InternalAnalysisTaskTest extends PersistenceCapableTest {

    @Test
    public void testIssue1574() {
        var project = new Project();
        project.setName("acme-app");
        project = qm.createProject(project, Collections.emptyList(), false);
        var component = new Component();
        component.setProject(project);
        component.setName("github.com/tidwall/gjson");
        component.setVersion("v1.6.0");
        component.setPurl("pkg:golang/github.com/tidwall/gjson@v1.6.0?type=module");
        component = qm.createComponent(component, false);

        var vulnerableSoftware = new VulnerableSoftware();
        vulnerableSoftware.setPurlType("golang");
        vulnerableSoftware.setPurlNamespace("github.com/tidwall");
        vulnerableSoftware.setPurlName("gjson");
        vulnerableSoftware.setVersionEndExcluding("1.6.5");
        vulnerableSoftware.setVulnerable(true);
        vulnerableSoftware = qm.persist(vulnerableSoftware);

        var vulnerability = new Vulnerability();
        vulnerability.setVulnId("GHSA-wjm3-fq3r-5x46");
        vulnerability.setSource(Vulnerability.Source.GITHUB);
        vulnerability.setVulnerableSoftware(List.of(vulnerableSoftware));
        qm.createVulnerability(vulnerability, false);

        new InternalAnalysisTask().analyze(List.of(component));

        final PaginatedResult vulnerabilities = qm.getVulnerabilities(component);
        assertThat(vulnerabilities.getTotal()).isEqualTo(1);
        assertThat(vulnerabilities.getList(Vulnerability.class).get(0).getVulnId()).isEqualTo("GHSA-wjm3-fq3r-5x46");
    }

    @Test
    public void testExactMatchWithNAUpdate() throws CpeParsingException, CpeEncodingException {
        var project = new Project();
        project.setName("acme-app");
        project = qm.createProject(project, Collections.emptyList(), false);
        var component = new Component();
        component.setProject(project);
        component.setGroup("xiph");
        component.setName("speex");
        component.setVersion("1.2");
        component.setCpe("cpe:2.3:a:xiph:speex:1.2:-:*:*:*:*:*:*");
        component = qm.createComponent(component, false);

        var vulnerableSoftware = ModelConverter.convertCpe23UriToVulnerableSoftware("cpe:2.3:a:xiph:speex:1.2:-:*:*:*:*:*:*");
        vulnerableSoftware = qm.persist(vulnerableSoftware);

        var vulnerability = new Vulnerability();
        vulnerability.setVulnId("CVE-2020-23904");
        vulnerability.setSource(Vulnerability.Source.NVD);
        vulnerability.setVulnerableSoftware(List.of(vulnerableSoftware));
        qm.createVulnerability(vulnerability, false);

        new InternalAnalysisTask().analyze(List.of(component));

        final PaginatedResult vulnerabilities = qm.getVulnerabilities(component);
        assertThat(vulnerabilities.getTotal()).isEqualTo(1);
        assertThat(vulnerabilities.getList(Vulnerability.class).get(0).getVulnId()).isEqualTo("CVE-2020-23904");
    }

    @Test
    public void testGitFalsePositives() {
        var project = new Project();
        project.setName("Test");
        project = qm.createProject(project, List.of(), false);
        var component = new Component();
        component.setProject(project);
        component.setName("git");
        component.setVersion("1:2.34.1-1ubuntu1.4");
        component.setPurl("pkg:deb/ubuntu/git@1%3A2.34.1-1ubuntu1.4?arch=amd64&distro=ubuntu-22.04");
        component.setCpe("cpe:2.3:a:git:git:1\\:2.34.1-1ubuntu1.4:*:*:*:*:*:*:*");
        component = qm.createComponent(component, false);

        //cpe:2.3:a:git:git:*:*:*:*:*:*:*:* ( |<=2.3.9 )
        String cpe23Uri = "cpe:2.3:a:git:git:*:*:*:*:*:*:*:*";
        VulnerableSoftware vulnerableSoftware = null;
        try {
            vulnerableSoftware = org.dependencytrack.parser.nvd.ModelConverter.convertCpe23UriToVulnerableSoftware(cpe23Uri);
            vulnerableSoftware.setVersionEndIncluding("2.3.9");
            vulnerableSoftware.setVulnerable(true);
        } catch (CpeParsingException | CpeEncodingException e) {
            assertThat(false);
        }
        assertThat(null != vulnerableSoftware);
        vulnerableSoftware = qm.persist(vulnerableSoftware);

        var vulnerability = new Vulnerability();
        vulnerability.setVulnId("CVE-2015-7545");
        vulnerability.setSource(Vulnerability.Source.NVD);
        vulnerability.setVulnerableSoftware(List.of(vulnerableSoftware));
        qm.createVulnerability(vulnerability, false);

        new InternalAnalysisTask().analyze(List.of(component));

        final PaginatedResult vulnerabilities = qm.getVulnerabilities(component);
        assertThat(vulnerabilities.getTotal()).isEqualTo(0);
        //assertThat(vulnerabilities.getList(Vulnerability.class).get(0).getVulnId()).isEqualTo("CVE-2015-7545");
    }

    @Test
    public void testGit() {
        var project = new Project();
        project.setName("Test");
        project = qm.createProject(project, List.of(), false);
        var component = new Component();
        component.setProject(project);
        component.setName("git");
        component.setVersion("1:2.3.9-1ubuntu1.4");
        component.setPurl("pkg:deb/ubuntu/git@1%3A2.3.9-1ubuntu1.4?arch=amd64&distro=ubuntu-22.04");
        component.setCpe("cpe:2.3:a:git:git:1\\:2.3.9-1ubuntu1.4:*:*:*:*:*:*:*");
        component = qm.createComponent(component, false);

        //cpe:2.3:a:git:git:*:*:*:*:*:*:*:* ( |<=2.3.9 )
        String cpe23Uri = "cpe:2.3:a:git:git:*:*:*:*:*:*:*:*";
        VulnerableSoftware vulnerableSoftware = null;
        try {
            vulnerableSoftware = org.dependencytrack.parser.nvd.ModelConverter.convertCpe23UriToVulnerableSoftware(cpe23Uri);
            vulnerableSoftware.setVersionEndIncluding("2.3.9");
            vulnerableSoftware.setVulnerable(true);
        } catch (CpeParsingException | CpeEncodingException e) {
            assertThat(false);
        }
        assertThat(null != vulnerableSoftware);
        vulnerableSoftware = qm.persist(vulnerableSoftware);

        var vulnerability = new Vulnerability();
        vulnerability.setVulnId("CVE-2015-7545");
        vulnerability.setSource(Vulnerability.Source.NVD);
        vulnerability.setVulnerableSoftware(List.of(vulnerableSoftware));
        qm.createVulnerability(vulnerability, false);

        new InternalAnalysisTask().analyze(List.of(component));

        final PaginatedResult vulnerabilities = qm.getVulnerabilities(component);
        assertThat(vulnerabilities.getTotal()).isEqualTo(1);
        //assertThat(vulnerabilities.getList(Vulnerability.class).get(0).getVulnId()).isEqualTo("CVE-2015-7545");
    }

    @Test
    public void testOpensslFalsePositive() {
        var project = new Project();
        project.setName("Test");
        project = qm.createProject(project, List.of(), false);
        var component = new Component();
        component.setProject(project);
        component.setName("git");
        component.setVersion("1.1.1n-0+deb11u3");
        component.setPurl("pkg:deb/debian/openssl@1.1.1n-0%20deb11u3?arch=amd64&distro=debian-11");
        component.setCpe("cpe:2.3:a:openssl:openssl:1.1.1n-0\\+deb11u3:*:*:*:*:*:*:*");
        component = qm.createComponent(component, false);

        String cpe23Uri = "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*";
        VulnerableSoftware vulnerableSoftware = null;
        try {
            vulnerableSoftware = org.dependencytrack.parser.nvd.ModelConverter.convertCpe23UriToVulnerableSoftware(cpe23Uri);
            vulnerableSoftware.setVersionStartIncluding("1.1.1");
            vulnerableSoftware.setVersionEndIncluding("1.1.1b");
            vulnerableSoftware.setVulnerable(true);
        } catch (CpeParsingException | CpeEncodingException e) {
            assertThat(false);
        }
        assertThat(null != vulnerableSoftware);
        vulnerableSoftware = qm.persist(vulnerableSoftware);

        var vulnerability = new Vulnerability();
        vulnerability.setVulnId("CVE-2015-7545");
        vulnerability.setSource(Vulnerability.Source.NVD);
        vulnerability.setVulnerableSoftware(List.of(vulnerableSoftware));
        qm.createVulnerability(vulnerability, false);

        new InternalAnalysisTask().analyze(List.of(component));

        final PaginatedResult vulnerabilities = qm.getVulnerabilities(component);
        assertThat(vulnerabilities.getTotal()).isEqualTo(0);
        //assertThat(vulnerabilities.getList(Vulnerability.class).get(0).getVulnId()).isEqualTo("CVE-2015-7545");
    }

    @Test
    public void testOpenssl() {
        var project = new Project();
        project.setName("Test");
        project = qm.createProject(project, List.of(), false);
        var component = new Component();
        component.setProject(project);
        component.setName("git");
        component.setVersion("1.1.1b-0+deb11u3");
        component.setPurl("pkg:deb/debian/openssl@1.1.1b-0%20deb11u3?arch=amd64&distro=debian-11");
        component.setCpe("cpe:2.3:a:openssl:openssl:1.1.1b-0\\+deb11u3:*:*:*:*:*:*:*");
        component = qm.createComponent(component, false);

        String cpe23Uri = "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*";
        VulnerableSoftware vulnerableSoftware = null;
        try {
            vulnerableSoftware = org.dependencytrack.parser.nvd.ModelConverter.convertCpe23UriToVulnerableSoftware(cpe23Uri);
            vulnerableSoftware.setVersionStartIncluding("1.1.1");
            vulnerableSoftware.setVersionEndIncluding("1.1.1b");
            vulnerableSoftware.setVulnerable(true);
        } catch (CpeParsingException | CpeEncodingException e) {
            assertThat(false);
        }
        assertThat(null != vulnerableSoftware);
        vulnerableSoftware = qm.persist(vulnerableSoftware);

        var vulnerability = new Vulnerability();
        vulnerability.setVulnId("CVE-2015-7545");
        vulnerability.setSource(Vulnerability.Source.NVD);
        vulnerability.setVulnerableSoftware(List.of(vulnerableSoftware));
        qm.createVulnerability(vulnerability, false);

        new InternalAnalysisTask().analyze(List.of(component));

        final PaginatedResult vulnerabilities = qm.getVulnerabilities(component);
        assertThat(vulnerabilities.getTotal()).isEqualTo(1);
        //assertThat(vulnerabilities.getList(Vulnerability.class).get(0).getVulnId()).isEqualTo("CVE-2015-7545");
    }

    @Test
    public void testCVE_2021_45967() {
        var project = new Project();
        project.setName("Test");
        project = qm.createProject(project, List.of(), false);
        var component = new Component();
        component.setProject(project);
        component.setName("product");
        component.setVersion("1.0.0");
        component.setCpe("cpe:2.3:a:*:product:1.0.0:*:*:*:*:*:*:*");
        component = qm.createComponent(component, false);

        String cpe23Uri = "cpe:2.3:a:vendor:*:*:*:*:*:*:*:*:*";
        VulnerableSoftware vulnerableSoftware = null;
        try {
            vulnerableSoftware = org.dependencytrack.parser.nvd.ModelConverter.convertCpe23UriToVulnerableSoftware(cpe23Uri);
            vulnerableSoftware.setVersionStartIncluding("1.0.0");
            vulnerableSoftware.setVersionEndIncluding("1.0.1");
            vulnerableSoftware.setVulnerable(true);
        } catch (CpeParsingException | CpeEncodingException e) {
            assertThat(false);
        }
        assertThat(null != vulnerableSoftware);
        vulnerableSoftware = qm.persist(vulnerableSoftware);

        var vulnerability = new Vulnerability();
        vulnerability.setVulnId("CVE-2021-45967");
        vulnerability.setSource(Vulnerability.Source.NVD);
        vulnerability.setVulnerableSoftware(List.of(vulnerableSoftware));
        qm.createVulnerability(vulnerability, false);

        new InternalAnalysisTask().analyze(List.of(component));

        final PaginatedResult vulnerabilities = qm.getVulnerabilities(component);
        assertThat(vulnerabilities.getTotal()).isEqualTo(0);
        //assertThat(vulnerabilities.getList(Vulnerability.class).get(0).getVulnId()).isEqualTo("CVE-2015-7545");
    }
}
