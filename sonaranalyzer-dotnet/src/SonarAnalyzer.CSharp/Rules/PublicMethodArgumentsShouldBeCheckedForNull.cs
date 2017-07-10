/*
 * SonarAnalyzer for .NET
 * Copyright (C) 2015-2017 SonarSource SA
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
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using SonarAnalyzer.Common;
using SonarAnalyzer.Helpers;
using SonarAnalyzer.Helpers.FlowAnalysis.Common;
using SonarAnalyzer.Helpers.FlowAnalysis.CSharp;
using ExplodedGraph = SonarAnalyzer.Helpers.FlowAnalysis.CSharp.ExplodedGraph;

namespace SonarAnalyzer.Rules.CSharp
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    [Rule(DiagnosticId)]
    public sealed class PublicMethodArgumentsShouldBeCheckedForNull : SonarDiagnosticAnalyzer
    {
        internal const string DiagnosticId = "S3900";
        private const string MessageFormat = "Refactor this method to add validation of parameter '{0}' before using it.";

        private static readonly DiagnosticDescriptor rule =
            DiagnosticDescriptorBuilder.GetDescriptor(DiagnosticId, MessageFormat, RspecStrings.ResourceManager);

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(rule);

        protected override void Initialize(SonarAnalysisContext context)
        {
            context.RegisterExplodedGraphBasedAnalysis((e, c) => CheckForNullDereference(e, c));
        }

        private static void CheckForNullDereference(ExplodedGraph explodedGraph, SyntaxNodeAnalysisContext context)
        {
            if (context.SemanticModel.Compilation.IsTest())
            {
                return;
            }

            var methodSymbol = context.SemanticModel.GetSymbolInfo(context.Node).Symbol
                ?? context.SemanticModel.GetDeclaredSymbol(context.Node);

            if (!methodSymbol.IsPubliclyAccessible())
            {
                return;
            }

            var nullPointerCheck = new NullPointerDereference.NullPointerCheck(explodedGraph);
            explodedGraph.AddExplodedGraphCheck(nullPointerCheck);

            var identifiers = new HashSet<IdentifierNameSyntax>();

            EventHandler<MemberAccessingEventArgs> memberAccessingHandler =
                (sender, args) => CollectMemberAccesses(args, identifiers, context.SemanticModel);

            nullPointerCheck.MemberAccessing += memberAccessingHandler;

            try
            {
                explodedGraph.Walk();
            }
            finally
            {
                nullPointerCheck.MemberAccessing -= memberAccessingHandler;
            }

            foreach (var identifier in identifiers)
            {
                context.ReportDiagnostic(Diagnostic.Create(rule, identifier.GetLocation(), identifier.Identifier.ValueText));
            }
        }

        private static void CollectMemberAccesses(MemberAccessingEventArgs args, HashSet<IdentifierNameSyntax> identifiers,
            SemanticModel semanticModel)
        {
            if (args.Symbol is IParameterSymbol &&
                !NullPointerDereference.NullPointerCheck.IsExtensionMethod(args.Identifier.Parent, semanticModel) &&
                !args.Symbol.HasConstraint(ObjectConstraint.NotNull, args.ProgramState))
            {
                identifiers.Add(args.Identifier);
            }
        }
    }
}
