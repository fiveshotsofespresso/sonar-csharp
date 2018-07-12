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
using SonarAnalyzer.Protobuf.Ucfg;

namespace SonarAnalyzer.ControlFlowGraph.CSharp
{
    /// <summary>
    /// High level UCFG Instruction factory that controls UcfgObjectFactory to create objects
    /// depending on the provided SyntaxNodes.
    /// </summary>
    internal class UcfgInstructionFactory
    {
        private static readonly IEnumerable<Instruction> NoInstructions = Enumerable.Empty<Instruction>();

        private readonly SemanticModel semanticModel;
        private readonly UcfgExpressionService expressionService;

        public UcfgInstructionFactory(SemanticModel semanticModel, UcfgExpressionService expressionService)
        {
            this.semanticModel = semanticModel;
            this.expressionService = expressionService;
        }

        public IEnumerable<Instruction> CreateFrom(SyntaxNode syntaxNode)
        {
            switch (syntaxNode)
            {
                case ObjectCreationExpressionSyntax objectCreation:
                    return ProcessObjectCreationExpression(objectCreation);

                case ArrayCreationExpressionSyntax arrayCreation:
                    return ProcessArrayCreationExpression(arrayCreation);

                case IdentifierNameSyntax identifierName:
                    return ProcessIdentifierName(identifierName);

                case GenericNameSyntax genericName:
                    return ProcessGenericName(genericName);

                case VariableDeclaratorSyntax variableDeclarator:
                    return ProcessVariableDeclarator(variableDeclarator);

                case BinaryExpressionSyntax binaryExpression:
                    return ProcessBinaryExpression(binaryExpression);

                case InvocationExpressionSyntax invocationExpression:
                    return ProcessInvocationExpression(invocationExpression);

                case AssignmentExpressionSyntax assignmentExpression:
                    return ProcessAssignmentExpression(assignmentExpression);

                case BaseMethodDeclarationSyntax methodDeclaration:
                    return ProcessBaseMethodDeclaration(methodDeclaration);

                case InstanceExpressionSyntax instanceExpression:
                    expressionService.Associate(instanceExpression, UcfgExpression.This);
                    return NoInstructions;

                case MemberAccessExpressionSyntax memberAccessExpression:
                    return ProcessMemberAccessExpression(memberAccessExpression);

                case ConstructorInitializerSyntax constructorInitializer:
                    return ProcessConstructorInitializer(constructorInitializer);

                case ElementAccessExpressionSyntax elementAccessExpression:
                    return ProcessElementAccessExpression(elementAccessExpression);

                default:
                    expressionService.Associate(syntaxNode, UcfgExpression.Constant);
                    return NoInstructions;
            }
        }

        public IEnumerable<Instruction> CreateFromAttributeSyntax(AttributeSyntax attributeSyntax, IMethodSymbol attributeCtor,
            string parameterName)
        {
            var targetOfAttribute = expressionService.GetExpression(attributeSyntax.Parent.Parent);

            return CreateAnnotateCall(attributeSyntax, attributeCtor.ReturnType, attributeCtor, targetOfAttribute)
                .Concat(CreateAnnotationCall(attributeSyntax, targetOfAttribute, expressionService.GetExpression(attributeSyntax)));
        }

        private IEnumerable<Instruction> ProcessConstructorInitializer(ConstructorInitializerSyntax constructorInitializer)
        {
            var chainedCtor = GetSymbol(constructorInitializer) as IMethodSymbol;
            if (chainedCtor == null)
            {
                return Enumerable.Empty<Instruction>();
            }

            return CreateMethodCall(constructorInitializer, chainedCtor, UcfgExpression.This,
                GetAdditionalArguments(constructorInitializer.ArgumentList));
        }

        private IEnumerable<Instruction> ProcessElementAccessExpression(ElementAccessExpressionSyntax elementAccessExpression)
        {
            if (!IsArray(elementAccessExpression.Expression))
            {
                expressionService.Associate(elementAccessExpression, UcfgExpression.Constant);
                return NoInstructions;
            }

            var targetObject = expressionService.GetExpression(elementAccessExpression.Expression);

            var elementAccess = expressionService.CreateArrayAccess(
                semanticModel.GetSymbolInfo(elementAccessExpression.Expression).Symbol, targetObject);

            // handling for parenthesized left side of an assignment (x[5]) = s
            var topParenthesized = elementAccessExpression.GetSelfOrTopParenthesizedExpression();

            // When the array access is on the left side of an assignment expression we will generate the
            // set instruction in the assignment expression handler, hence we just associate the two
            // syntax and the ucfg expression.
            if (IsLeftSideOfAssignment(topParenthesized))
            {
                expressionService.Associate(elementAccessExpression, elementAccess);
                return NoInstructions;
            }

            // for anything else we generate __arrayGet instruction
            return CreateArrayGetCall(elementAccessExpression, elementAccess.TypeSymbol, targetObject);

            bool IsLeftSideOfAssignment(SyntaxNode syntaxNode) =>
                syntaxNode.Parent is AssignmentExpressionSyntax assignmentExpression &&
                assignmentExpression.Left == syntaxNode;

            bool IsArray(ExpressionSyntax expression)
            {
                var elementAccessType = semanticModel.GetTypeInfo(expression).ConvertedType;
                return elementAccessType != null
                    && elementAccessType.TypeKind == TypeKind.Array;
            }
        }

        private IEnumerable<Instruction> ProcessObjectCreationExpression(ObjectCreationExpressionSyntax objectCreationExpression)
        {
            var methodSymbol = GetSymbol(objectCreationExpression) as IMethodSymbol;
            if (methodSymbol == null)
            {
                return NoInstructions;
            }

            // A call to a constructor should look like:
            // %X := new Ctor()
            // %X+1 := Ctor_MethodId [ %X params ]
            // variable := __id [ %X ]
            // As all instructions creation result in the SyntaxNode being associated with the return variable, we would
            // end up with variable := __id [ %X+1 ] (the objectCreationExpression node being now associated to %X+1).
            // To avoid this behavior, we associate the method call to the type of the objectCreationExpression
            var newObjectCall = CreateNewObject(objectCreationExpression, methodSymbol,
                expressionService.CreateVariable(methodSymbol.ReturnType));

            return newObjectCall.Concat(
                CreateMethodCall(objectCreationExpression.Type, methodSymbol,
                    expressionService.GetExpression(objectCreationExpression),
                    GetAdditionalArguments(objectCreationExpression.ArgumentList)));
        }

        private IEnumerable<Instruction> ProcessArrayCreationExpression(ArrayCreationExpressionSyntax arrayCreationExpression)
        {
            var arrayTypeSymbol = semanticModel.GetTypeInfo(arrayCreationExpression).Type as IArrayTypeSymbol;
            if (arrayTypeSymbol == null)
            {
                expressionService.Associate(arrayCreationExpression, UcfgExpression.Constant);
                return NoInstructions;
            }

            // A call that constructs an array should look like:
            // Code: var x = new string[42];
            // %0 := new string[]       // <-- created by this method
            // x = __id [ %0 ]          // <-- created by the method that handles the assignment

            return CreateNewArray(arrayCreationExpression, arrayTypeSymbol,
                    expressionService.CreateVariable(arrayTypeSymbol));
        }

        private IEnumerable<Instruction> ProcessGenericName(GenericNameSyntax genericName)
        {
            var namedTypeSymbol = GetSymbol(genericName) as INamedTypeSymbol;

            UcfgExpression target = null;

            if (namedTypeSymbol != null)
            {
                target = namedTypeSymbol.IsStatic
                ? expressionService.CreateClassName(namedTypeSymbol)
                : UcfgExpression.This;
            }

            var ucfgExpression = expressionService.Create(namedTypeSymbol, target);
            expressionService.Associate(genericName, ucfgExpression);

            return NoInstructions;
        }

        private IEnumerable<Instruction> ProcessIdentifierName(IdentifierNameSyntax identifierName)
        {
            if (identifierName.Parent is MemberAccessExpressionSyntax memberAccess &&
                memberAccess.Name == identifierName)
            {
                return NoInstructions;
            }

            var target = UcfgExpression.Unknown;
            var assignmentExpression = identifierName.Parent as AssignmentExpressionSyntax;

            if (assignmentExpression != null &&
                assignmentExpression.Parent is InitializerExpressionSyntax initializerExpression)
            {
                // When we process a field or property, and it is part of a new class initialization we should retrieve the
                // correct target (i.e. the class instantiation).
                target = expressionService.GetExpression(initializerExpression.Parent);
            }

            var symbol = GetSymbol(identifierName);

            if (target == UcfgExpression.Unknown)
            {
                if (symbol.IsStatic)
                {
                    target = symbol is INamedTypeSymbol namedTypeSymbol
                        ? expressionService.CreateClassName(namedTypeSymbol)
                        : expressionService.CreateClassName(symbol.ContainingType);
                }
                else
                {
                    target = UcfgExpression.This;
                }
            }

            var ucfgExpression = expressionService.Create(symbol, target);
            expressionService.Associate(identifierName, ucfgExpression);

            if (assignmentExpression?.Left != identifierName &&
                ucfgExpression is UcfgExpression.PropertyAccessExpression propertyExpression)
            {
                return CreateMethodCall(identifierName, propertyExpression.GetMethodSymbol, propertyExpression.Target);
            }

            return NoInstructions;
        }

        private IEnumerable<Instruction> ProcessVariableDeclarator(VariableDeclaratorSyntax variableDeclarator)
        {
            if (variableDeclarator.Initializer == null)
            {
                return NoInstructions;
            }

            var toExpression = expressionService.Create(semanticModel.GetDeclaredSymbol(variableDeclarator), null);
            var fromExpression = expressionService.GetExpression(variableDeclarator.Initializer.Value);

            return CreateIdCall(variableDeclarator, toExpression, fromExpression);
        }

        private IEnumerable<Instruction> ProcessBinaryExpression(BinaryExpressionSyntax binaryExpression)
        {
            var binaryExpressionTypeSymbol = this.semanticModel.GetTypeInfo(binaryExpression).ConvertedType;

            if (binaryExpression.OperatorToken.IsKind(SyntaxKind.PlusToken))
            {
                var leftExpression = expressionService.GetExpression(binaryExpression.Left);
                var rightExpression = expressionService.GetExpression(binaryExpression.Right);

                // TODO: Handle property (for non string) get on left or right
                // TODO: Handle implicit ToString
                if (leftExpression.TypeSymbol.Is(KnownType.System_String) ||
                    rightExpression.TypeSymbol.Is(KnownType.System_String))
                {
                    return CreateConcatCall(binaryExpression, binaryExpressionTypeSymbol, leftExpression, rightExpression);
                }
            }

            expressionService.Associate(binaryExpression, UcfgExpression.Constant);
            return NoInstructions;
        }

        private IEnumerable<Instruction> ProcessInvocationExpression(InvocationExpressionSyntax invocationExpression)
        {
            var methodSymbol = GetSymbol(invocationExpression) as IMethodSymbol;
            if (methodSymbol == null)
            {
                expressionService.Associate(invocationExpression, UcfgExpression.Constant);
                return NoInstructions;
            }

            var methodExpression = expressionService.GetExpression(invocationExpression.Expression)
                as UcfgExpression.MethodAccessExpression;
            if (methodExpression == null)
            {
                expressionService.Associate(invocationExpression, UcfgExpression.Constant);
                return NoInstructions;
            }

            UcfgExpression targetExpression;
            UcfgExpression memberAccessArgument = null;
            if (IsCalledAsExtension(methodSymbol))
            {
                // First argument is the class name (static method call)
                targetExpression = expressionService.CreateClassName(methodSymbol.ContainingType);

                // Second argument is the left side of the invocation
                if (invocationExpression.Expression is MemberAccessExpressionSyntax memberAccessExpression)
                {
                    memberAccessArgument = expressionService.GetExpression(memberAccessExpression.Expression);
                }
                else
                {
                    throw new UcfgException("Unexpected state, method called as extension of a member but there is no " +
                        "member access available.");
                }
            }
            else
            {
                targetExpression = methodExpression.Target;
            }

            var additionalArguments = new List<UcfgExpression>();
            if (memberAccessArgument != null)
            {
                additionalArguments.Add(memberAccessArgument);
            }
            additionalArguments.AddRange(GetAdditionalArguments(invocationExpression.ArgumentList));

            return CreateMethodCall(invocationExpression, methodSymbol, targetExpression, additionalArguments.ToArray());

            bool IsCalledAsExtension(IMethodSymbol method) => method.ReducedFrom != null;
        }

        private IEnumerable<Instruction> ProcessAssignmentExpression(AssignmentExpressionSyntax assignmentExpression)
        {
            var instructions = new List<Instruction>();

            var leftExpression = expressionService.GetExpression(assignmentExpression.Left);

            // Because of the current shape of the CFG, it is possible not to have the left expression already processed but
            // only when left is identifier for field, local variable or parameter.
            // In this case, we need to manually call process identifier on left part before being able to retrieve from the cache.
            if (leftExpression == UcfgExpression.Unknown &&
                assignmentExpression.Left is IdentifierNameSyntax identifierNameSyntax)
            {
                instructions.AddRange(ProcessIdentifierName(identifierNameSyntax));
                leftExpression = expressionService.GetExpression(assignmentExpression.Left);
            }

            var rightExpression = expressionService.GetExpression(assignmentExpression.Right);

            // handle left part of the assignment
            switch (leftExpression)
            {
                case UcfgExpression.PropertyAccessExpression leftPropertyExpression
                    when (leftPropertyExpression.SetMethodSymbol != null):
                    instructions.AddRange(CreateMethodCall(assignmentExpression, leftPropertyExpression.SetMethodSymbol,
                        leftPropertyExpression.Target, rightExpression));
                    break;

                case UcfgExpression.FieldAccessExpression fieldExpression:
                case UcfgExpression.VariableExpression variableExpression:
                    instructions.AddRange(CreateIdCall(assignmentExpression, leftExpression, rightExpression));
                    break;

                case UcfgExpression.ElementAccessExpression elementExpression:
                    instructions.AddRange(
                        CreateArraySetCall(assignmentExpression, elementExpression.TypeSymbol, elementExpression.Target,
                            rightExpression));
                    break;

                default:
                    break;
            }

            return instructions;
        }

        private IEnumerable<Instruction> ProcessBaseMethodDeclaration(BaseMethodDeclarationSyntax methodDeclaration)
        {
            var methodSymbol = this.semanticModel.GetDeclaredSymbol(methodDeclaration);

            foreach (var parameter in methodSymbol.Parameters)
            {
                expressionService.Associate(parameter.DeclaringSyntaxReferences.First().GetSyntax(),
                    expressionService.Create(parameter, null));
            }

            return CreateEntryPointCall(methodDeclaration, methodSymbol.ReturnType, methodDeclaration.ParameterList);
        }

        private IEnumerable<Instruction> ProcessMemberAccessExpression(MemberAccessExpressionSyntax memberAccessExpression)
        {
            var memberAccessSymbol = GetSymbol(memberAccessExpression);
            var leftSideExpression = expressionService.GetExpression(memberAccessExpression.Expression);

            var instructions = new List<Instruction>();

            if (leftSideExpression is UcfgExpression.FieldAccessExpression fieldExpression
                && memberAccessSymbol is IFieldSymbol fieldSymbol)
            {
                var fieldAccessAsNewVariable = expressionService.CreateVariable(fieldExpression.TypeSymbol);
                instructions.AddRange(CreateIdCall(memberAccessExpression.Expression, fieldAccessAsNewVariable, fieldExpression));
                leftSideExpression = expressionService.GetExpression(memberAccessExpression.Expression);
            }

            var ucfgExpression = expressionService.Create(memberAccessSymbol, leftSideExpression);
            expressionService.Associate(memberAccessExpression, ucfgExpression);

            var assignmentExpression = memberAccessExpression.Parent as AssignmentExpressionSyntax;
            if (assignmentExpression?.Left != memberAccessExpression &&
                ucfgExpression is UcfgExpression.PropertyAccessExpression propertyExpression)
            {
                instructions.AddRange(CreateMethodCall(memberAccessExpression, propertyExpression.GetMethodSymbol,
                    propertyExpression.Target));
            }

            return instructions;
        }

        public IEnumerable<Instruction> CreateConcatCall(SyntaxNode syntaxNode, ITypeSymbol nodeTypeSymbol, UcfgExpression left,
            UcfgExpression right)
        {
            return CreateFunctionCall(syntaxNode, expressionService.CreateVariable(nodeTypeSymbol), "__concat", left, right);
        }

        public IEnumerable<Instruction> CreateIdCall(SyntaxNode syntaxNode, UcfgExpression to, UcfgExpression value)
        {
            return CreateFunctionCall(syntaxNode, to, "__id", value);
        }

        public IEnumerable<Instruction> CreateAnnotateCall(SyntaxNode syntaxNode, ITypeSymbol nodeTypeSymbol,
            IMethodSymbol attributeMethodSymbol, UcfgExpression target)
        {
            return CreateFunctionCall(syntaxNode, expressionService.CreateVariable(nodeTypeSymbol), "__annotate",
                expressionService.CreateConstant(attributeMethodSymbol), target);
        }

        public IEnumerable<Instruction> CreateAnnotationCall(SyntaxNode syntaxNode, UcfgExpression to, UcfgExpression value)
        {
            return CreateFunctionCall(syntaxNode, to, "__annotation", value);
        }

        public IEnumerable<Instruction> CreateArrayGetCall(SyntaxNode syntaxNode, ITypeSymbol nodeTypeSymbol,
            UcfgExpression target)
        {
            return CreateFunctionCall(syntaxNode, expressionService.CreateVariable(nodeTypeSymbol), "__arrayGet", target);
        }

        public IEnumerable<Instruction> CreateArraySetCall(SyntaxNode syntaxNode, ITypeSymbol nodeTypeSymbol,
            UcfgExpression target, UcfgExpression value)
        {
            return CreateFunctionCall(syntaxNode, expressionService.CreateVariable(nodeTypeSymbol), "__arraySet", target, value);
        }

        public IEnumerable<Instruction> CreateEntryPointCall(SyntaxNode syntaxNode, ITypeSymbol nodeTypeSymbol,
            ParameterListSyntax parameterList)
        {
            return CreateFunctionCall(syntaxNode, expressionService.CreateVariable(nodeTypeSymbol), "__entrypoint",
                parameterList.Parameters.Select(expressionService.GetExpression).ToArray());
        }

        private IEnumerable<Instruction> CreateMethodCall(SyntaxNode syntaxNode, IMethodSymbol methodSymbol, UcfgExpression target,
            params UcfgExpression[] additionalArguments)
        {
            // FIX ME: uncomment me and fix the target for some cases
            //if (target is UcfgExpression.FieldAccessExpression ||
            //    target is UcfgExpression.ConstantExpression)
            //{
            //    throw new UcfgException("Expecting the first argument of a function call to be 'ThisExpression', " +
            //        $"'VariableExpression' or 'ClassNameExpression' but got '{target.GetType().Name}'.");
            //}

            return CreateFunctionCall(syntaxNode, expressionService.CreateVariable(methodSymbol.ReturnType),
                methodSymbol.ToUcfgMethodId(), new[] { target }.Concat(additionalArguments).ToArray());
        }

        private IEnumerable<Instruction> CreateFunctionCall(SyntaxNode syntaxNode, UcfgExpression assignedTo,
            string methodIdentifier, params UcfgExpression[] arguments)
        {
            if (syntaxNode is ObjectCreationExpressionSyntax)
            {
                throw new UcfgException("Expecting this method not to be called for nodes of type 'ObjectCreationExpressionSyntax'.");
            }

            expressionService.Associate(syntaxNode, assignedTo);

            var instruction = new Instruction
            {
                Assigncall = new AssignCall
                {
                    Location = syntaxNode.GetUcfgLocation(),
                    MethodId = methodIdentifier
                }
            };
            instruction.Assigncall.Args.AddRange(arguments.Select(a => a.Expression));
            assignedTo.ApplyAsTarget(instruction);

            return new[] { instruction };
        }

        private IEnumerable<Instruction> CreateNewObject(ObjectCreationExpressionSyntax syntaxNode,
            IMethodSymbol ctorSymbol, UcfgExpression callTarget)
        {
            expressionService.Associate(syntaxNode, callTarget);

            var instruction = new Instruction
            {
                NewObject = new NewObject
                {
                    Location = syntaxNode.GetUcfgLocation(),
                    Type = expressionService.CreateClassName(ctorSymbol.ContainingType).Expression.Classname.Classname
                }
            };
            callTarget.ApplyAsTarget(instruction);

            return new[] { instruction };
        }

        private IEnumerable<Instruction> CreateNewArray(ArrayCreationExpressionSyntax syntaxNode,
            IArrayTypeSymbol arrayTypeSymbol, UcfgExpression callTarget)
        {
            expressionService.Associate(syntaxNode, callTarget);

            var instruction = new Instruction
            {
                NewObject = new NewObject
                {
                    Location = syntaxNode.GetUcfgLocation(),
                    Type = arrayTypeSymbol.ToDisplayString()
                }
            };
            callTarget.ApplyAsTarget(instruction);

            return new[] { instruction };
        }

        private ISymbol GetSymbol(SyntaxNode syntaxNode) =>
            semanticModel.GetSymbolInfo(syntaxNode).Symbol;

        private UcfgExpression[] GetAdditionalArguments(ArgumentListSyntax argumentList)
        {
            if (argumentList == null)
            {
                return new UcfgExpression[0];
            }

            return argumentList.Arguments
                .Select(a => a.Expression)
                .Select(expressionService.GetExpression)
                .ToArray();
        }
    }
}
