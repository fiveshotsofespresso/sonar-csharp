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

using System.Collections.Generic;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SonarAnalyzer.Helpers;
using SonarAnalyzer.SymbolicExecution.ControlFlowGraph;
using CfgBlock = SonarAnalyzer.SymbolicExecution.ControlFlowGraph.Block;
using UcfgBlock = SonarAnalyzer.Protobuf.Ucfg.BasicBlock;
using UcfgExpression = SonarAnalyzer.Protobuf.Ucfg.Expression;
using UcfgInstruction = SonarAnalyzer.Protobuf.Ucfg.Instruction;
using UcfgLocation = SonarAnalyzer.Protobuf.Ucfg.Location;

namespace SonarAnalyzer.Rules.CSharp
{
    public class UcfgBuilder
    {
        /// <summary>
        /// The string constant representation in the Sonar Security engine (Java part). When
        /// an instruction receives or returns a type that is not string we use this instead
        /// of a variable.
        /// </summary>
        private static readonly UcfgExpression ConstantExpression = new UcfgExpression
        {
            Const = new Protobuf.Ucfg.Constant { Value = "\"\"" }
        };

        private readonly Protobuf.Ucfg.UCFG ucfg = new Protobuf.Ucfg.UCFG();
        private readonly BlockIdCache blockIdCache = new BlockIdCache();
        private readonly SemanticModel semanticModel;

        private IMethodSymbol methodSymbol;
        private SyntaxNode methodLikeNode;

        public UcfgBuilder(SemanticModel semanticModel)
        {
            this.semanticModel = semanticModel;
        }

        public UcfgBuilder FromSignature(IMethodSymbol methodSymbol, SyntaxNode methodLikeNode)
        {
            this.methodSymbol = methodSymbol;
            this.methodLikeNode = methodLikeNode;

            ucfg.MethodId = GetMethodId(methodSymbol);
            ucfg.Location = ToUcfgLocation(methodLikeNode.GetLocation());
            ucfg.Parameters.AddRange(methodSymbol.GetParameters().Select(p => p.Name));

            return this;
        }

        public UcfgBuilder WithBlocks(IEnumerable<CfgBlock> cfgBlocks)
        {
            ucfg.BasicBlocks.AddRange(cfgBlocks.Select(BuildBlock));

            return this;
        }

        public UcfgBuilder WithEntryPoint(CfgBlock entryBlock)
        {
            if (methodLikeNode is BaseMethodDeclarationSyntax methodDeclaration &&
                EntryPointRecognizer.IsEntryPoint(methodSymbol))
            {
                var entryPointBlock = CreateEntryPointBlock(blockIdCache.GetOrAdd(entryBlock), methodDeclaration);
                ucfg.BasicBlocks.Add(entryPointBlock);
                ucfg.Entries.Add(entryPointBlock.Id);
            }
            else
            {
                ucfg.Entries.Add(blockIdCache.GetOrAdd(entryBlock));
            }

            return this;
        }

        public Protobuf.Ucfg.UCFG Build() =>
            IsValid(ucfg) ? ucfg : null;

        internal static bool IsValid(Protobuf.Ucfg.UCFG ucfg)
        {
            var existingBlockIds = new HashSet<string>(ucfg.BasicBlocks.Select(b => b.Id));

            return ucfg.BasicBlocks.All(HasTerminator)
                && ucfg.BasicBlocks.All(JumpsToExistingBlock)
                && ucfg.Entries.All(existingBlockIds.Contains);

            bool HasTerminator(UcfgBlock block) =>
                block.Jump != null || block.Ret != null;

            bool JumpsToExistingBlock(UcfgBlock block) =>
                block.Jump == null || block.Jump.Destinations.All(existingBlockIds.Contains);
        }

        private UcfgBlock BuildBlock(CfgBlock cfgBlock)
        {
            var ucfgBlock = new UcfgBlock { Id = blockIdCache.GetOrAdd(cfgBlock) };

            var instructionBuilder = new UcfgInstructionBuilder(semanticModel, ucfgBlock);

            foreach (var instruction in cfgBlock.Instructions)
            {
                instructionBuilder.BuildInstruction(instruction);
            }

            if (cfgBlock is JumpBlock jump)
            {
                instructionBuilder.BuildInstruction(jump.JumpNode);
            }

            if (cfgBlock is ExitBlock exit)
            {
                ucfgBlock.Ret = new Protobuf.Ucfg.Return { ReturnedExpression = ConstantExpression };
            }

            if (ucfgBlock.TerminatorCase == UcfgBlock.TerminatorOneofCase.None)
            {
                // No return was created from JumpBlock or ExitBlock, wire up the successor blocks
                ucfgBlock.Jump = new Protobuf.Ucfg.Jump();
                ucfgBlock.Jump.Destinations.AddRange(cfgBlock.SuccessorBlocks.Select(x => blockIdCache.GetOrAdd(cfgBlock)));
            }

            return ucfgBlock;
        }

        private UcfgBlock CreateEntryPointBlock(string currentEntryBlockId, BaseMethodDeclarationSyntax methodDeclaration)
        {
            var basicBlock = new UcfgBlock
            {
                Id = blockIdCache.GetOrAdd(new TemporaryBlock()),
                Jump = new Protobuf.Ucfg.Jump { Destinations = { currentEntryBlockId } }
            };

            var instructionBuilder = new UcfgInstructionBuilder(semanticModel, basicBlock);
            instructionBuilder.BuildEntryPointInstruction(methodDeclaration);

            foreach (var parameter in methodSymbol.Parameters)
            {
                instructionBuilder.BuildAttributeInstructions(parameter);
            }

            return basicBlock;
        }

        /// <summary>
        /// Returns UCFG Location that represents the location of the provided SyntaxNode
        /// in SonarQube coordinates - 1-based line numbers and 0-based columns (line offsets).
        /// Roslyn coordinates are 0-based.
        /// </summary>
        private static UcfgLocation ToUcfgLocation(Location location)
        {
            var lineSpan = location.GetLineSpan();

            return new UcfgLocation
            {
                FileId = location.SourceTree.FilePath,
                StartLine = lineSpan.StartLinePosition.Line + 1,
                StartLineOffset = lineSpan.StartLinePosition.Character,
                EndLine = lineSpan.EndLinePosition.Line + 1,
                EndLineOffset = lineSpan.EndLinePosition.Character - 1,
            };
        }

        internal static string GetMethodId(IMethodSymbol methodSymbol)
        {
            switch (methodSymbol?.MethodKind)
            {
                case MethodKind.ExplicitInterfaceImplementation:
                    return GetMethodId(methodSymbol.ExplicitInterfaceImplementations.First());

                case MethodKind.ReducedExtension:
                    return methodSymbol.ReducedFrom.ToDisplayString();

                default:
                    return methodSymbol?.OriginalDefinition?.ToDisplayString() ?? KnownMethodId.Unknown;
            }
        }

        private class BlockIdCache
        {
            /// <summary>
            /// This cache of UCFG block ID is required because we are not sure of the order we iterate through the CFG blocks and
            /// because we might have loops between CFG blocks.
            /// </summary>
            private readonly Dictionary<CfgBlock, string> cfgBlockToUcfgBlockId
                = new Dictionary<CfgBlock, string>();
            private int blockCounter;

            public string GetOrAdd(CfgBlock cfgBlock) =>
                cfgBlockToUcfgBlockId.GetOrAdd(cfgBlock, b => $"{blockCounter++}");
        }

        private class UcfgInstructionBuilder
        {
            private readonly Dictionary<SyntaxNode, UcfgExpression> cfgInstructionToUcfgExpressionCache
                = new Dictionary<SyntaxNode, UcfgExpression>();
            private readonly SemanticModel semanticModel;
            private readonly UcfgBlock basicBlock;

            private int tempVariablesCounter;

            public UcfgInstructionBuilder(SemanticModel semanticModel, UcfgBlock basicBlock)
            {
                this.semanticModel = semanticModel;
                this.basicBlock = basicBlock;
            }

            public void BuildAttributeInstructions(IParameterSymbol parameter)
            {
                foreach (var attribute in parameter.GetAttributes().Where(a => a.AttributeConstructor != null))
                {
                    var attributeVariable = CreateTempVariable();

                    AddInstructionToBlock(
                        attribute.ApplicationSyntaxReference.GetSyntax(),
                        methodId: GetMethodId(attribute.AttributeConstructor),
                        variable: attributeVariable);

                    AddInstructionToBlock(
                        attribute.ApplicationSyntaxReference.GetSyntax(),
                        methodId: KnownMethodId.Annotation,
                        variable: parameter.Name,
                        arguments: CreateVariableExpression(attributeVariable));
                }
            }

            public void BuildEntryPointInstruction(BaseMethodDeclarationSyntax methodDeclaration)
            {
                AddInstructionToBlock(
                    methodDeclaration,
                    methodId: KnownMethodId.EntryPoint,
                    variable: CreateTempVariable(),
                    arguments: methodDeclaration.ParameterList.Parameters
                        .Select(parameter => parameter.Identifier.ValueText)
                        .Select(CreateVariableExpression)
                        .ToArray());
            }

            public UcfgExpression BuildInstruction(SyntaxNode cfgInstruction) =>
                cfgInstructionToUcfgExpressionCache.GetOrAdd(cfgInstruction.RemoveParentheses(), BuildInstructionImpl);

            private UcfgExpression BuildInstructionImpl(SyntaxNode syntaxNode)
            {
                switch (syntaxNode.Kind())
                {
                    case SyntaxKind.AddExpression:
                        return BuildBinaryExpression((BinaryExpressionSyntax)syntaxNode);

                    case SyntaxKind.SimpleAssignmentExpression:
                        return BuildAssignment((AssignmentExpressionSyntax)syntaxNode);

                    case SyntaxKind.InvocationExpression:
                        return BuildInvocation((InvocationExpressionSyntax)syntaxNode);

                    case SyntaxKind.IdentifierName:
                        return BuildIdentifierName((IdentifierNameSyntax)syntaxNode);

                    case SyntaxKind.VariableDeclarator:
                        BuildVariableDeclarator((VariableDeclaratorSyntax)syntaxNode);
                        return null;

                    case SyntaxKind.ReturnStatement:
                        BuildReturn((ReturnStatementSyntax)syntaxNode);
                        return null;

                    case SyntaxKind.ObjectCreationExpression:
                        return BuildObjectCreation((ObjectCreationExpressionSyntax)syntaxNode);

                    default:
                        // do nothing
                        return ConstantExpression;
                }
            }

            private UcfgExpression BuildObjectCreation(ObjectCreationExpressionSyntax objectCreation)
            {
                if (!(semanticModel.GetSymbolInfo(objectCreation).Symbol is IMethodSymbol ctorSymbol))
                {
                    return ConstantExpression;
                }

                var arguments = BuildArguments(objectCreation.ArgumentList).ToArray();

                // Create instruction only when the method accepts/returns string,
                // or when at least one of its arguments is known to be a string.
                // Since we generate Const expressions for everything that is not
                // a string, checking if the arguments are Var expressions should
                // be enough to ensure they are strings.
                if (!AcceptsOrReturnsString(ctorSymbol) &&
                    !arguments.Any(expression => expression.Var != null))
                {
                    return ConstantExpression;
                }

                var instruction = AddInstructionToBlock(
                    objectCreation,
                    methodId: GetMethodId(ctorSymbol),
                    variable: CreateTempVariable(),
                    arguments: arguments);

                return ctorSymbol.ReturnType.Is(KnownType.System_String)
                    ? CreateVariableExpression(instruction.Variable)
                    : ConstantExpression;
            }

            private UcfgExpression BuildIdentifierName(IdentifierNameSyntax identifier)
            {
                var identifierSymbol = semanticModel.GetSymbolInfo(identifier).Symbol;

                if (identifierSymbol is IPropertySymbol property)
                {
                    var instruction = AddInstructionToBlock(
                        identifier,
                        methodId: GetMethodId(property.GetMethod),
                        variable: CreateTempVariable());

                    return CreateVariableExpression(instruction.Variable);
                }
                else if (IsLocalVarOrParameterOfTypeString(identifierSymbol))
                {
                    return CreateVariableExpression(identifierSymbol.Name);
                }
                else
                {
                    return ConstantExpression;
                }
            }

            private void BuildVariableDeclarator(VariableDeclaratorSyntax variableDeclarator)
            {
                if (variableDeclarator.Initializer == null)
                {
                    return;
                }

                var variable = semanticModel.GetDeclaredSymbol(variableDeclarator);
                if (IsLocalVarOrParameterOfTypeString(variable))
                {
                    AddInstructionToBlock(
                        variableDeclarator,
                        methodId: KnownMethodId.Assignment,
                        variable: variable.Name,
                        arguments: BuildInstruction(variableDeclarator.Initializer.Value));
                }
            }

            private UcfgExpression BuildBinaryExpression(BinaryExpressionSyntax binaryExpression)
            {
                var instruction = AddInstructionToBlock(
                    binaryExpression,
                    methodId: KnownMethodId.Concatenation,
                    variable: CreateTempVariable(),
                    arguments: new[] { BuildInstruction(binaryExpression.Right), BuildInstruction(binaryExpression.Left) });

                return CreateVariableExpression(instruction.Variable);
            }

            private void BuildReturn(ReturnStatementSyntax returnStatement)
            {
                basicBlock.Ret = new Protobuf.Ucfg.Return
                {
                    Location = ToUcfgLocation(returnStatement.GetLocation()),
                    ReturnedExpression = returnStatement.Expression != null
                        ? BuildInstruction(returnStatement.Expression)
                        : ConstantExpression,
                };
            }

            private UcfgExpression BuildInvocation(InvocationExpressionSyntax invocation)
            {
                if (!(semanticModel.GetSymbolInfo(invocation).Symbol is IMethodSymbol methodSymbol))
                {
                    return ConstantExpression;
                }

                // The arguments are built in advance to allow nested instructions
                // to be added, regardless of whether the current invocation is going
                // to be added to the UCFG or not. For example: LogStatus(StoreInDb(str1 + str2))
                // should add 'str1 + str2' and 'StoreInDb(string)', but not 'void LogStatus(int)'
                var arguments = BuildArguments(invocation, methodSymbol).ToArray();

                // Add instruction to UCFG only when the method accepts/returns string,
                // or when at least one of its arguments is known to be a string.
                // Since we generate Const expressions for everything that is not
                // a string, checking if the arguments are Var expressions should
                // be enough to ensure they are strings.
                if (!AcceptsOrReturnsString(methodSymbol) &&
                    !arguments.Any(IsVariable))
                {
                    return ConstantExpression;
                }

                var instruction = AddInstructionToBlock(
                    invocation,
                    methodId: GetMethodId(methodSymbol),
                    variable: CreateTempVariable(),
                    arguments: arguments);

                return methodSymbol.ReturnType.Is(KnownType.System_String)
                    ? CreateVariableExpression(instruction.Variable)
                    : ConstantExpression;

                bool IsVariable(UcfgExpression expression) =>
                    expression.Var != null;
            }

            private IEnumerable<UcfgExpression> BuildArguments(ArgumentListSyntax argumentList)
            {
                if (argumentList == null)
                {
                    yield break;
                }

                foreach (var argument in argumentList.Arguments)
                {
                    yield return BuildInstruction(argument.Expression);
                }
            }

            private IEnumerable<UcfgExpression> BuildArguments(InvocationExpressionSyntax invocation, IMethodSymbol methodSymbol)
            {
                if (IsInstanceMethodOnString(methodSymbol) ||
                    IsExtensionMethodCalledAsExtension(methodSymbol))
                {
                    if (invocation.Expression is MemberAccessExpressionSyntax memberAccess)
                    {
                        // add the string to the beginning of the arguments list
                        yield return BuildInstruction(memberAccess.Expression);
                    }
                }

                if (invocation.ArgumentList == null)
                {
                    yield break;
                }

                foreach (var argument in invocation.ArgumentList.Arguments)
                {
                    yield return BuildInstruction(argument.Expression);
                }
            }

            private UcfgExpression BuildAssignment(AssignmentExpressionSyntax assignment)
            {
                var left = semanticModel.GetSymbolInfo(assignment.Left).Symbol;
                var right = BuildInstruction(assignment.Right);

                if (IsLocalVarOrParameterOfTypeString(left))
                {
                    var instruction = AddInstructionToBlock(
                        assignment,
                        methodId: KnownMethodId.Assignment,
                        variable: left.Name,
                        arguments: right);

                    return CreateVariableExpression(instruction.Variable);
                }
                else if (left is IPropertySymbol property &&
                    property.SetMethod != null &&
                    AcceptsOrReturnsString(property.SetMethod))
                {
                    var instruction = AddInstructionToBlock(
                        assignment,
                        methodId: GetMethodId(property.SetMethod),
                        variable: CreateTempVariable(),
                        arguments: right);

                    return CreateVariableExpression(instruction.Variable);
                }
                else
                {
                    return ConstantExpression;
                }
            }

            private static bool IsExtensionMethodCalledAsExtension(IMethodSymbol methodSymbol) =>
                methodSymbol.ReducedFrom != null;

            private static bool IsInstanceMethodOnString(IMethodSymbol methodSymbol) =>
                methodSymbol.ContainingType.Is(KnownType.System_String) && !methodSymbol.IsStatic;

            private static bool IsLocalVarOrParameterOfTypeString(ISymbol symbol) =>
                symbol is ILocalSymbol local && local.Type.Is(KnownType.System_String) ||
                symbol is IParameterSymbol parameter && parameter.Type.Is(KnownType.System_String);

            private string CreateTempVariable() =>
                $"%{tempVariablesCounter++}";

            private static UcfgExpression CreateVariableExpression(string name) =>
                new UcfgExpression { Var = new Protobuf.Ucfg.Variable { Name = name } };

            private static bool AcceptsOrReturnsString(IMethodSymbol methodSymbol) =>
                methodSymbol.ReturnType.Is(KnownType.System_String) ||
                methodSymbol.Parameters.Any(p => p.Type.Is(KnownType.System_String));

            private UcfgInstruction AddInstructionToBlock(SyntaxNode node, string methodId, string variable,
                params UcfgExpression[] arguments)
            {
                var instruction = new UcfgInstruction
                {
                    Location = ToUcfgLocation(node.GetLocation()),
                    MethodId = methodId,
                    Variable = variable ?? ConstantExpression.Const.Value,
                };
                instruction.Args.AddRange(arguments);

                this.basicBlock.Instructions.Add(instruction);

                return instruction;
            }
        }
    }
}
