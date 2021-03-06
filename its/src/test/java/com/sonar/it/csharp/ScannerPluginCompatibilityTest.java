/*
 * SonarSource :: C# :: ITs :: Plugin
 * Copyright (C) 2011-2018 SonarSource SA
 * mailto:info AT sonarsource DOT com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
package com.sonar.it.csharp;

import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import com.sonar.orchestrator.Orchestrator;
import com.sonar.orchestrator.build.BuildResult;
import com.sonar.orchestrator.build.ScannerForMSBuild;

import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

public class ScannerPluginCompatibilityTest {

  @ClassRule
  public static final Orchestrator orchestrator = Tests.ORCHESTRATOR;

  @Rule
  public TemporaryFolder temp = new TemporaryFolder();

  @Before
  public void init() throws Exception {
    orchestrator.resetData();
  }

  @Test
  public void scanner_2_1_plugin_greater_than_6_should_fail_with_nice_message() throws Exception {
    Path projectDir = Tests.projectDir(temp, "NoCoverageOnTests");
    BuildResult result = orchestrator.executeBuildQuietly(
      ScannerForMSBuild.create(projectDir.toFile())
        .setScannerVersion("2.1.0.0")
        .addArgument("begin")
        .setProjectKey("FailingTest")
        .setProjectName("FailingTest")
        .setProjectVersion("1.0"));

    assertThat(result.getLastStatus()).isNotEqualTo(0);
    assertThat(result.getLogs())
      .contains("The C# plugin installed on the SonarQube server is not compatible with the SonarQube analysis agent " +
        "(i.e. the MSBuild.SonarQube.Runner.exe, or the build automation task). " +
        "Either check the compatibility matrix or get the latest versions for both.");
  }
}
