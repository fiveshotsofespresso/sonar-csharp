﻿/*
 * SonarAnalyzer for .NET
 * Copyright (C) 2015-2018 SonarSource SA
 * mailto: contact AT sonarsource DOT com
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

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using Google.Protobuf;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using SonarAnalyzer.Common;
using SonarAnalyzer.ControlFlowGraph.CSharp;
using SonarAnalyzer.Helpers;
using SonarAnalyzer.Protobuf.Ucfg;

namespace SonarAnalyzer.Rules.CSharp
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class UcfgGenerator : SonarDiagnosticAnalyzer
    {
        internal const string DiagnosticId = "S9999-ucfg";
        private const string Title = "UCFG generator.";

        private static bool ShouldGenerateDot =>
            Environment.GetEnvironmentVariable("SONARANALYZER_GENERATE_DOT")?.ToUpper() == "TRUE";

        private static readonly DiagnosticDescriptor rule =
            DiagnosticDescriptorBuilder.GetUtilityDescriptor(DiagnosticId, Title, SourceScope.Main);

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(rule);

        private readonly ImmutableHashSet<string> SecurityRules = ImmutableHashSet
            .Create("S2091", "S3649", "S2631", "S2083", "S2078", "S2076");

        private string protobufDirectory;
        private int protobufFileIndex = 0;

        /// <summary>
        /// Contains the build ID as set by Scanner for MSBuild. Usually it is a number.
        /// We include this in the protobuf file names because the Sonar Security plugin
        /// is unable to read files from subfolders.
        /// </summary>
        private string projectBuildId;

        private readonly IAnalyzerConfiguration configuration;

        public UcfgGenerator()
            : this(new DefaultAnalyzerConfiguration())
        {
        }

        public UcfgGenerator(IAnalyzerConfiguration configuration)
        {
            this.configuration = configuration;
        }

        protected override void Initialize(SonarAnalysisContext context)
        {
            context.RegisterCompilationStartAction(
                cc =>
                {
                    configuration.Read(cc.Options);

                    if (string.IsNullOrEmpty(configuration.ProjectOutputPath) ||
                        !configuration.EnabledRules.Any(SecurityRules.Contains))
                    {
                        return;
                    }

                    InitProtobufDirectory();

                    protobufFileIndex = 0;

                    cc.RegisterSyntaxNodeActionInNonGenerated(
                        c => WriteUCFG<ConstructorDeclarationSyntax>(c, x => x.Body),
                        SyntaxKind.ConstructorDeclaration);

                    cc.RegisterSyntaxNodeActionInNonGenerated(
                        c => WriteUCFG<MethodDeclarationSyntax>(c, x => (CSharpSyntaxNode)x.Body ?? x.ExpressionBody?.Expression),
                        SyntaxKind.MethodDeclaration);

                    cc.RegisterSyntaxNodeActionInNonGenerated(
                        c => WriteUCFG<OperatorDeclarationSyntax>(c, x => (CSharpSyntaxNode)x.Body ?? x.ExpressionBody?.Expression),
                        SyntaxKind.OperatorDeclaration);

                    cc.RegisterSyntaxNodeActionInNonGenerated(
                        c => WriteUCFG<AccessorDeclarationSyntax>(c, node => node.Body),
                        SyntaxKind.GetAccessorDeclaration,
                        SyntaxKind.SetAccessorDeclaration);

                    cc.RegisterSyntaxNodeActionInNonGenerated(
                        c => WriteUCFG<PropertyDeclarationSyntax>(c, node => node.ExpressionBody?.Expression),
                        SyntaxKind.PropertyDeclaration);
                });
        }

        internal /*for testing*/ static bool IsValid(UCFG ucfg)
        {
            var existingBlockIds = new HashSet<string>(ucfg.BasicBlocks.Select(b => b.Id));

            return ucfg.BasicBlocks.All(HasTerminator)
                && ucfg.BasicBlocks.All(JumpsToExistingBlock)
                && ucfg.Entries.All(existingBlockIds.Contains);

            bool HasTerminator(BasicBlock block) =>
                block.Jump != null || block.Ret != null;

            bool JumpsToExistingBlock(BasicBlock block) =>
                block.Jump == null || block.Jump.Destinations.All(existingBlockIds.Contains);
        }

        private void WriteUCFG<TDeclarationSyntax>(SyntaxNodeAnalysisContext context, Func<TDeclarationSyntax, CSharpSyntaxNode> getBody)
            where TDeclarationSyntax : SyntaxNode
        {
            var declaration = (TDeclarationSyntax)context.Node;

            var symbol = context.SemanticModel.GetDeclaredSymbol(declaration);

            var methodSymbol = (symbol is IPropertySymbol propertySymbol)
                ? propertySymbol.GetMethod // We are in PropertyDeclarationSyntax
                : symbol as IMethodSymbol; // all other are methods

            if (methodSymbol == null ||
                methodSymbol.IsAbstract ||
                methodSymbol.IsExtern ||
                !CSharpControlFlowGraph.TryGet(getBody(declaration), context.SemanticModel, out var cfg))
            {
                return;
            }

            var ucfg = new UcfgFactory(context.SemanticModel)
                .Create(declaration, methodSymbol, cfg);

            if (IsValid(ucfg))
            {
                var fileName = $"{projectBuildId}_{Interlocked.Increment(ref protobufFileIndex)}";

                WriteProtobuf(ucfg, Path.Combine(protobufDirectory, $"ucfg_{fileName}.pb"));

                if (ShouldGenerateDot)
                {
                    WriteDot(Path.Combine(protobufDirectory, $"ucfg_{fileName}.dot"), writer => UcfgSerializer.Serialize(ucfg, writer));
                    WriteDot(Path.Combine(protobufDirectory, $"cfg_{fileName}.dot"), writer => CfgSerializer.Serialize(ucfg.MethodId, cfg, writer));
                }
            }
        }

        protected /*for testing*/ virtual void WriteDot(string filePath, Action<StreamWriter> write)
        {
            using (var writer = File.CreateText(filePath))
            {
                write(writer);
            }
        }

        protected /*for testing*/ virtual void WriteProtobuf(UCFG ucfg, string fileName)
        {
            using (var stream = File.Create(fileName))
            {
                ucfg.WriteTo(stream);
            }
        }

        private void InitProtobufDirectory()
        {
            // the current compilation output dir is "<root>/.sonarqube/out/<index>" where index is 0, 1, 2, etc.

            // the configuration.ProjectOutputPath should already be checked for null at this point
            Debug.Assert(configuration.ProjectOutputPath != null);

            // "<root>/.sonarqube/out/0" -> "0" etc.
            projectBuildId = Path.GetFileName(configuration.ProjectOutputPath);

            // "<root>/.sonarqube/out/0" -> "<root>/.sonarqube/out/ucfg_cs"
            protobufDirectory = Path.Combine(Path.GetDirectoryName(configuration.ProjectOutputPath), $"ucfg_{AnalyzerLanguage.CSharp}");

            Directory.CreateDirectory(protobufDirectory);
        }
    }
}
