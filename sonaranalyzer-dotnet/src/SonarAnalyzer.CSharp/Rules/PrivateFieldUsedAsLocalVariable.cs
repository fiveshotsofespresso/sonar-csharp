/*
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
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using SonarAnalyzer.Common;
using SonarAnalyzer.Helpers;

namespace SonarAnalyzer.Rules.CSharp
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    [Rule(DiagnosticId)]
    public class PrivateFieldUsedAsLocalVariable : SonarDiagnosticAnalyzer
    {
        internal const string DiagnosticId = "S1450";
        private const string MessageFormat = "Remove the '{0}' field and declare it as a local variable in the relevant methods.";

        private static readonly DiagnosticDescriptor rule =
            DiagnosticDescriptorBuilder.GetDescriptor(DiagnosticId, MessageFormat, RspecStrings.ResourceManager);

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(rule);

        protected sealed override void Initialize(SonarAnalysisContext context)
        {
            context.RegisterSyntaxNodeActionInNonGenerated(
                c =>
                {
                    var classNode = c.Node as TypeDeclarationSyntax;
                    if (classNode != null && classNode.Modifiers.Any(SyntaxKind.PartialKeyword))
                    {
                        // Not supported
                        return;
                    }

                    var fieldSymbolToPrivateFieldMap = GetPrivateFields(classNode, c.SemanticModel);
                    var refSymbolToRefNodeToFieldMap = GetReferencesByEnclosingSymbol(classNode, fieldSymbolToPrivateFieldMap, c.SemanticModel);

                    var classSymbol = c.SemanticModel.GetDeclaredSymbol(classNode);
                    if (classSymbol == null)
                    {
                        return;
                    }

                    var classMethods = classSymbol.GetMembers().Where(m => m.Kind == SymbolKind.Method).ToHashSet();

                    ExcludePrivateFieldsBasedOnReferences(fieldSymbolToPrivateFieldMap, refSymbolToRefNodeToFieldMap, classMethods);
                    ExcludePrivateFieldsBasedOnCompilerErrors(fieldSymbolToPrivateFieldMap, refSymbolToRefNodeToFieldMap, classMethods,
                        classNode, c.SemanticModel.Compilation);

                    foreach (var privateField in fieldSymbolToPrivateFieldMap.GetIncludedFields())
                    {
                        c.ReportDiagnosticWhenActive(Diagnostic.Create(rule, privateField.Syntax.GetLocation(),
                            privateField.Symbol.Name));
                    }
                },
                SyntaxKind.ClassDeclaration, SyntaxKind.StructDeclaration);
        }

        private static FieldSymbolToPrivateFieldMap GetPrivateFields(TypeDeclarationSyntax classNode,
            SemanticModel semanticModel)
        {
            var privateFields = classNode.Members
                        .Where(m => m.IsKind(SyntaxKind.FieldDeclaration))
                        .Cast<FieldDeclarationSyntax>()
                        .Where(f => !f.AttributeLists.Any())
                        .SelectMany(f => f.Declaration.Variables.Select(
                            v => new PrivateField(v, semanticModel.GetDeclaredSymbol(v) as IFieldSymbol)))
                        .Where(f => f.Symbol != null && f.Symbol.DeclaredAccessibility == Accessibility.Private);

            var map = new FieldSymbolToPrivateFieldMap();
            foreach(var privateField in privateFields)
            {
                map.Add(privateField.Symbol, privateField);
            }
            return map;
        }

        private static IDictionary<ISymbol, ReferencingNodeToFieldSymbolMap> GetReferencesByEnclosingSymbol(
            SyntaxNode node,
            FieldSymbolToPrivateFieldMap privateFieldsMap,
            SemanticModel semanticModel)
        {
            var privateFieldNames = privateFieldsMap.Keys.Select(s => s.Name).ToHashSet();

            var potentialReferences = node.DescendantNodes()
                .Where(n => n.IsKind(SyntaxKind.IdentifierName))
                .Cast<IdentifierNameSyntax>()
                .Where(id => privateFieldNames.Contains(id.Identifier.ValueText));

            var builder = new Dictionary<ISymbol, ReferencingNodeToFieldSymbolMap>();
            foreach (var potentialReference in potentialReferences)
            {
                var referencedSymbol = semanticModel.GetSymbolInfo(potentialReference).Symbol as IFieldSymbol;
                if (referencedSymbol == null || !privateFieldsMap.ContainsKey(referencedSymbol))
                {
                    continue;
                }

                SyntaxNode referenceSyntax = potentialReference;
                while (referenceSyntax.Parent != null &&
                       referencedSymbol.Equals(semanticModel.GetSymbolInfo(referenceSyntax.Parent).Symbol))
                {
                    referenceSyntax = referenceSyntax.Parent;
                }

                if (referenceSyntax.Parent != null &&
                    referenceSyntax.Parent.IsKind(SyntaxKind.ConditionalAccessExpression))
                {
                    referenceSyntax = referenceSyntax.Parent;
                }


                var referringSymbol = semanticModel.GetEnclosingSymbol(potentialReference.SpanStart);
                if (!builder.ContainsKey(referringSymbol))
                {
                    builder.Add(referringSymbol, new ReferencingNodeToFieldSymbolMap());
                }

                builder[referringSymbol].Add(referenceSyntax, referencedSymbol);
            }

            return builder;
        }

        private static void ExcludePrivateFieldsBasedOnReferences(
            FieldSymbolToPrivateFieldMap fieldSymbolToPrivateFieldMap,
            IDictionary<ISymbol, ReferencingNodeToFieldSymbolMap> refSymbolToRefNodeToFieldMap,
            ISet<ISymbol> classMethods)
        {
            var referencedAtLeastOnceFromClassMethod = new HashSet<IFieldSymbol>();

            foreach (var references in refSymbolToRefNodeToFieldMap)
            {
                // If referred to from outside a class method then exclude the field
                if (!classMethods.Contains(references.Key))
                {
                    fieldSymbolToPrivateFieldMap.MarkFieldsAsExcluded(references.Value.Values);
                    continue;
                }

                // Exclude usages that aren't simple field references
                foreach (var refNodeToField in references.Value)
                {
                    referencedAtLeastOnceFromClassMethod.Add(refNodeToField.Value);

                    if (!IsReferenceToSingleFieldValue(refNodeToField))
                    {
                        fieldSymbolToPrivateFieldMap.MarkFieldAsExcluded(refNodeToField.Value);
                    }
                }
            }

            // Exclude fields that aren't referenced by any private method
            fieldSymbolToPrivateFieldMap.MarkFieldsAsExcluded(
                fieldSymbolToPrivateFieldMap.Keys.Except(referencedAtLeastOnceFromClassMethod));
        }

        private static bool IsReferenceToSingleFieldValue(KeyValuePair<SyntaxNode, IFieldSymbol> reference)
        {
            if (reference.Key.IsKind(SyntaxKind.IdentifierName) || reference.Value.IsStatic)
            {
                return true;
            }

            if (reference.Key is MemberAccessExpressionSyntax memberAccess && memberAccess.Expression.IsKind(SyntaxKind.ThisExpression))
            {
                return true;
            }

            if (reference.Key is ConditionalAccessExpressionSyntax conditionalAccess && conditionalAccess.Expression.IsKind(SyntaxKind.ThisExpression))
            {
                return true;
            }

            return false;
        }

        private static void ExcludePrivateFieldsBasedOnCompilerErrors(
            FieldSymbolToPrivateFieldMap privateFields,
            IDictionary<ISymbol, ReferencingNodeToFieldSymbolMap> referencesByEnclosingSymbol,
            IEnumerable<ISymbol> classMethods,
            TypeDeclarationSyntax classNode,
            Compilation compilation)
        {
            var replacements = new Dictionary<SyntaxNode, BlockSyntax>();
            foreach (var classMethod in classMethods.Where(m => referencesByEnclosingSymbol.ContainsKey(m)))
            {
                var references = referencesByEnclosingSymbol[classMethod].Where(r => !privateFields[r.Value].Excluded)
                    .ToImmutableDictionary(kv => kv.Key, kv => kv.Value);
                if (TryRewriteMethodBody(privateFields, references, classMethod, out var body, out var newBody))
                {
                    replacements.Add(body, newBody);
                }
            }

            if (!replacements.Any())
            {
                return;
            }

            var newSyntaxRoot = classNode.SyntaxTree.GetRoot().ReplaceSyntax(
                replacements.Keys,
                (original, partiallyRewritten) => replacements[original],
                null,
                null,
                null,
                null);
            var newSyntaxTree = classNode.SyntaxTree.WithRootAndOptions(newSyntaxRoot,
                classNode.SyntaxTree.Options);
            var newCompilation = CSharpCompilation.Create(nameof(PrivateFieldUsedAsLocalVariable),
                new[] { newSyntaxTree }, compilation.References, compilation.Options as CSharpCompilationOptions);

            var diagnostics = newCompilation.GetDiagnostics();
            foreach (var privateField in privateFields.GetIncludedFields())
            {
                if (diagnostics.Any(d => d.Id == WellKnownDiagnosticIds.ERR_UseDefViolation
                                         && d.GetMessage().Contains(privateField.UniqueName)))
                {
                    privateField.Excluded = true;
                }
            }
        }

        private static bool TryRewriteMethodBody(
            FieldSymbolToPrivateFieldMap privateFields,
            IDictionary<SyntaxNode, IFieldSymbol> references,
            ISymbol classMethod,
            out BlockSyntax body,
            out BlockSyntax newBody)
        {
            if (!references.Any())
            {
                body = null;
                newBody = null;

                return false;
            }

            if (!TryGetMemberBody(classMethod, out body))
            {
                // We don't know how the fields are being used within this method
                privateFields.MarkFieldsAsExcluded(references.Values);
 
                newBody = null;

                return false;
            }

            newBody = RewriteBody(privateFields, body, references, out var rewrittenNodes);

            return !ExcludePrivateFieldsBasedOnRewrittenNodes(privateFields, references, rewrittenNodes);
        }

        private static bool TryGetMemberBody(ISymbol memberSymbol, out BlockSyntax body)
        {
            body = null;

            var syntax = memberSymbol.DeclaringSyntaxReferences.SingleOrDefault()?.GetSyntax();
            if (syntax != null)
            {
                if (syntax is BaseMethodDeclarationSyntax methodSyntax)
                {
                    body = methodSyntax.Body;
                }

                if (syntax is AccessorDeclarationSyntax accessorSyntax)
                {
                    body = accessorSyntax.Body;
                }
            }

            return body != null;
        }

        private static BlockSyntax RewriteBody(
            FieldSymbolToPrivateFieldMap privateFields,
            BlockSyntax body,
            IDictionary<SyntaxNode, IFieldSymbol> references,
            out ISet<SyntaxNode> rewrittenNodes)
        {
            var symbolsToRewrite = references.Values.ToHashSet();

            var localDeclaration = SyntaxFactory.LocalDeclarationStatement(
                SyntaxFactory.VariableDeclaration(
                    SyntaxFactory.PredefinedType(
                        SyntaxFactory.Token(SyntaxKind.IntKeyword)).WithTrailingTrivia(SyntaxFactory.Space),
                    SyntaxFactory.SeparatedList(symbolsToRewrite.Select(
                        s => SyntaxFactory.VariableDeclarator(privateFields[s].UniqueName)))));

            var rewrittenNodesBuilder = new HashSet<SyntaxNode>();
            var newBody = body.ReplaceSyntax(
                references.Keys,
                (original, partiallyRewritten) =>
                {
                    rewrittenNodesBuilder.Add(original);
                    return SyntaxFactory.IdentifierName(privateFields[references[original]].UniqueName);
                },
                null,
                null,
                null,
                null);

            var newStatements = newBody.Statements.Insert(0, localDeclaration);
            newBody = newBody.WithStatements(newStatements);

            rewrittenNodes = rewrittenNodesBuilder;

            return newBody;
        }

        private static bool ExcludePrivateFieldsBasedOnRewrittenNodes(
            FieldSymbolToPrivateFieldMap privateFields,
            IDictionary<SyntaxNode, IFieldSymbol> references,
            ISet<SyntaxNode> rewrittenNodes)
        {
            var partiallyRewrittenSymbols = references
                .Where(r => !rewrittenNodes.Contains(r.Key))
                .Select(r => r.Value)
                .ToHashSet();

            privateFields.MarkFieldsAsExcluded(partiallyRewrittenSymbols);

            var allSymbolsToRewrite = references.Values.ToHashSet();

            return partiallyRewrittenSymbols.Count == allSymbolsToRewrite.Count;
        }

        private class PrivateField
        {
            public PrivateField(VariableDeclaratorSyntax syntax, IFieldSymbol symbol)
            {
                Syntax = syntax;
                Symbol = symbol;
                UniqueName = nameof(PrivateFieldUsedAsLocalVariable) + Guid.NewGuid().ToString("N");
                Excluded = false;
            }

            public VariableDeclaratorSyntax Syntax { get; private set; }
            public IFieldSymbol Symbol { get; private set; }
            public string UniqueName { get; private set; }
            public bool Excluded { get; set; }
        }

        private class FieldSymbolToPrivateFieldMap : Dictionary<IFieldSymbol, PrivateField>
        {
            public void MarkFieldsAsExcluded(IEnumerable<IFieldSymbol> fields)
            {
                foreach (var field in fields)
                {
                    MarkFieldAsExcluded(field);
                }
            }

            public void MarkFieldAsExcluded(IFieldSymbol fieldSymbol)
            {
                Debug.Assert(this.ContainsKey(fieldSymbol), "Expecting supplied field symbol to be in the map");
                if (this.TryGetValue(fieldSymbol, out PrivateField privateField))
                {
                    privateField.Excluded = true;
                }
            }

            public IEnumerable<PrivateField> GetIncludedFields() =>
                this.Values.Where(pf => !pf.Excluded);
        }

        private class ReferencingNodeToFieldSymbolMap : Dictionary<SyntaxNode, IFieldSymbol>
        {
        }

    }
}
