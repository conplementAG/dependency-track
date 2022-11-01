package org.dependencytrack.tasks.scanners;

import alpine.persistence.PaginatedResult;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerableSoftware;
import org.junit.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class InternalAnalysisTaskTest extends PersistenceCapableTest {

    @Test
    public void testIssue1574() {
        var project = new Project();
        project.setName("acme-app");
        project = qm.createProject(project, List.of(), false);
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
    public void testGitFalsePositives() {
        var project = new Project();
        project.setName("Test");
        project = qm.createProject(project, List.of(), false);
        var component = new Component();
        component.setProject(project);
        component.setName("git");
        component.setVersion("1:2.34.1-1ubuntu1.4");
        component.setPurl("pkg:deb/ubuntu/git@1%3A2.34.1-1ubuntu1.4?arch=amd64&distro=ubuntu-22.04");
        component.setCpe("cpe:2.3:a:git:git:1\:2.34.1-1ubuntu1.4:*:*:*:*:*:*:*");
        component = qm.createComponent(component, false);

        //cpe:2.3:a:git_project:git:*:*:*:*:*:*:*:* ( |<=2.3.9 )
        var vulnerableSoftware = new VulnerableSoftware();
        vulnerableSoftware.setPurlType("golang");
        vulnerableSoftware.setPurlNamespace("github.com/tidwall");
        vulnerableSoftware.setPurlName("gjson");
        vulnerableSoftware.setVersionEndExcluding("2.3.9");
        vulnerableSoftware.setVulnerable(true);
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

}