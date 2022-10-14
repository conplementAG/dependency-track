/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.tasks.scanners;

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import org.dependencytrack.event.InternalAnalysisEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.persistence.QueryManager;
import us.springett.parsers.cpe.CpeParser;
import us.springett.parsers.cpe.exceptions.CpeParsingException;

import java.util.List;

/**
 * Subscriber task that performs an analysis of component using internal CPE/PURL data.
 *
 * @author Steve Springett
 * @since 3.6.0
 */
public class InternalAnalysisTask extends AbstractVulnerableSoftwareAnalysisTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(InternalAnalysisTask.class);

    public AnalyzerIdentity getAnalyzerIdentity() {
        return AnalyzerIdentity.INTERNAL_ANALYZER;
    }

    /**
     * {@inheritDoc}
     */
    public void inform(final Event e) {
        if (e instanceof InternalAnalysisEvent) {
            if (!super.isEnabled(ConfigPropertyConstants.SCANNER_INTERNAL_ENABLED)) {
                return;
            }
            final InternalAnalysisEvent event = (InternalAnalysisEvent)e;
            LOGGER.info("Starting internal analysis task");
            if (event.getComponents().size() > 0) {
                analyze(event.getComponents());
            }
            LOGGER.info("Internal analysis complete");
        }
    }

    /**
     * Determines if the {@link InternalAnalysisTask} is capable of analyzing the specified Component.
     *
     * @param component the Component to analyze
     * @return true if InternalAnalysisTask should analyze, false if not
     */
    public boolean isCapable(final Component component) {
        return component.getCpe() != null || component.getPurl() != null;
    }

    /**
     * Analyzes a list of Components.
     * @param components a list of Components
     */
    public void analyze(final List<Component> components) {
        final boolean fuzzyEnabled = super.isEnabled(ConfigPropertyConstants.SCANNER_INTERNAL_FUZZY_ENABLED);
        final boolean excludeComponentsWithPurl = super.isEnabled(ConfigPropertyConstants.SCANNER_INTERNAL_FUZZY_EXCLUDE_PURL);
        try (QueryManager qm = new QueryManager()) {
            for (final Component c : components) {
                final Component component = qm.getObjectByUuid(Component.class, c.getUuid()); // Refresh component and attach to current pm.
                if (component == null) continue;
                versionRangeAnalysis(qm, component);
                if (fuzzyEnabled) {
                    if (component.getPurl() == null || !excludeComponentsWithPurl) {
                        fuzzyCpeAnalysis(qm, component);
                    }
                }
            }
        }
    }

    private void versionRangeAnalysis(final QueryManager qm, final Component component) {
        us.springett.parsers.cpe.Cpe parsedCpe = null;
        if (component.getCpe() != null) {
            try {
                parsedCpe = CpeParser.parse(component.getCpe());
            } catch (CpeParsingException e) {
                LOGGER.warn("An error occurred while parsing: " + component.getCpe() + " - The CPE is invalid and will be discarded. " + e.getMessage());
            }
        }

        // https://github.com/DependencyTrack/dependency-track/issues/1574
        // Some ecosystems use the "v" version prefix (e.g. v1.2.3) for their components.
        // However, both the NVD and GHSA store versions without that prefix.
        // For this reason, the prefix is stripped before running analyzeVersionRange.
        //
        // REVISIT THIS WHEN ADDING NEW VULNERABILITY SOURCES!
        String componentVersion;
        if (parsedCpe != null) {
            componentVersion = parsedCpe.getVersion();
        } else if (component.getPurl() != null) {
            componentVersion = component.getPurl().getVersion();
        } else {
            // Catch cases where the CPE couldn't be parsed and no PURL exists.
            // Should be rare, but could lead to NPEs later.
            LOGGER.debug("Neither CPE nor PURL of component " + component.getUuid() + " provide a version - skipping analysis");
            return;
        }
        if (componentVersion.length() > 1 && componentVersion.startsWith("v")) {
            componentVersion = componentVersion.substring(1);
        }

        // Ubuntu specifica
        if(null != component.getPurl())
        {
            String strCoordinate = component.getPurl().getCoordinates();
            LOGGER.info("Post processing: " + componentVersion + " of " + strCoordinate);

            if(strCoordinate.contains("pkg:deb/ubuntu") || strCoordinate.contains("pkg:deb/debian"))
            {
                //pkg:deb/ubuntu
                //1:1.2.11.dfsg-2ubuntu9 	--> 1.2.11
                //pkg:deb/debian
                //1:1.2.11.dfsg-2+deb11u1 --> 1.2.11
                String[] parts = componentVersion.split(":");
                if(parts.length > 1)
                {
                    componentVersion = "";
                    for (int i=1; i<parts.length;i++)
                    {
                        componentVersion += parts[i];
                    }
                }

                parts = componentVersion.split(".dfsg");
                if(parts.length > 1)
                {
                    componentVersion = "";
                    for (int i=0; i<parts.length-1;i++)
                    {
                        componentVersion += parts[i];
                    }
                }

                LOGGER.info("Post processing of component version: Debian/Ubuntu to" + componentVersion);
            }
            else if(strCoordinate.contains("pkg:alpine"))
            {
                //pkg:alpine
                //1.2.11-r3 --> 1.2.11
                String[] parts = componentVersion.split("-r");
                if(parts.length > 1)
                {
                    componentVersion = "";
                    for (int i=0; i<parts.length-1;i++)
                    {
                        componentVersion += parts[i];
                    }
                }
                LOGGER.info("Post processing of component version: Alpine to" + componentVersion);
            }
        }

        if (parsedCpe != null) {
            final List<VulnerableSoftware> vsList = qm.getAllVulnerableSoftware(parsedCpe.getPart().getAbbreviation(), parsedCpe.getVendor(), parsedCpe.getProduct(), component.getPurl());
            super.analyzeVersionRange(qm, vsList, componentVersion, parsedCpe.getUpdate(), component);
        } else {
            final List<VulnerableSoftware> vsList = qm.getAllVulnerableSoftware(null, null, null, component.getPurl());
            super.analyzeVersionRange(qm, vsList, componentVersion, null, component);
        }
    }

    private void fuzzyCpeAnalysis(final QueryManager qm, final Component component) {
        //TODO
    }
}
