/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "ESTreeIRGen.h"
#include "hermes/Regex/RegexSerialization.h"
#include "hermes/Support/UTF8.h"

#include "llvh/ADT/ScopeExit.h"

namespace hermes {
namespace irgen {

static llvh::StringRef propertyKeyAsString(
    llvh::SmallVectorImpl<char> &storage, ESTree::Node *Key);

Value *ESTreeIRGen::genExpression(ESTree::Node *expr, Identifier nameHint) {
  LLVM_DEBUG(
      llvh::dbgs() << "IRGen expression of type " << expr->getNodeName()
                   << "\n");
  IRBuilder::ScopedLocationChange slc(Builder, expr->getDebugLoc());

  if (auto *op = llvh::dyn_cast<ESTree::NativeDerivedSuperOperationNode>(expr)) {
    const bool forward = op->_operation->str() == "default_super";
    if (!curFunction()->derivedThis ||
        (!forward && op->_operation->str() != "super") ||
        op->_arguments.size() < 2 || (forward && op->_arguments.size() != 3)) {
      Builder.getModule()->getContext().getSourceErrorManager().error(
          expr->getSourceRange(), "[NATIVE_DERIVED_INVALID_IR] CONSTRUCTOR_CONTEXT");
      return Builder.getLiteralUndefined();
    }
    auto it = op->_arguments.begin();
    auto *ctor = &*it++; auto *initialize = &*it++;
    if (!llvh::isa<ESTree::IdentifierNode>(ctor) ||
        !llvh::isa<ESTree::IdentifierNode>(initialize)) {
      Builder.getModule()->getContext().getSourceErrorManager().error(
          expr->getSourceRange(), "[NATIVE_DERIVED_INVALID_IR] IDENTITY_BINDING");
      return Builder.getLiteralUndefined();
    }
    auto *parent = genBuiltinCall(BuiltinMethod::HermesBuiltin_getSuperConstructor,
        {genExpression(ctor)});
    auto *newTarget = cast<Variable>(curFunction()->capturedNewTarget);
    auto *target = Builder.createLoadFrameInst(newTarget, currentIRScope_);
    Value *constructed;
    bool spread = false;
    for (auto arg = it; arg != op->_arguments.end(); ++arg)
      spread |= llvh::isa<ESTree::SpreadElementNode>(&*arg);
    if (forward) {
                                                                             
      constructed = genBuiltinCall(BuiltinMethod::HermesBuiltin_constructWithNewTarget,
          {parent, genExpression(&*it), target});
    } else if (spread) {
                                                                               
      ESTree::NodeList arguments;
      arguments.splice(arguments.end(), op->_arguments, it, op->_arguments.end());
      auto *array = genArrayFromElements(arguments);
      op->_arguments.splice(op->_arguments.end(), arguments);
      constructed = genBuiltinCall(BuiltinMethod::HermesBuiltin_constructWithNewTarget,
          {parent, array, target});
    } else {
      ConstructInst::ArgumentList arguments;
      for (; it != op->_arguments.end(); ++it) arguments.push_back(genExpression(&*it));
      constructed = Builder.createConstructInst(parent, target, arguments);
    }
    genBuiltinCall(BuiltinMethod::HermesBuiltin_assertDerivedUninitialized,
        {Builder.createLoadFrameInst(curFunction()->derivedThis, currentIRScope_)});
    emitStore(constructed, curFunction()->derivedThis, false);
    Builder.createCallInst(CallInst::kNoTextifiedCallee,
        genExpression(initialize), constructed, {});
    return constructed;
  }

                                                                           
  if (auto *op = llvh::dyn_cast<ESTree::NativeClassDefinitionOperationNode>(expr)) {
    const auto name = op->_operation->str();
    if(name=="anonymous_expression") {
      if(op->_arguments.size()!=1 ||
         !llvh::isa<ESTree::ArrowFunctionExpressionNode>(&op->_arguments.front())) {
        Builder.getModule()->getContext().getSourceErrorManager().error(
            expr->getSourceRange(),"[NATIVE_CLASS_INVALID_IR] EXPRESSION_WRAPPER");
        return Builder.getLiteralUndefined();
      }
      auto *wrapper=genExpression(&op->_arguments.front());
      Value *hint=nameHint.isValid()?Builder.getLiteralString(nameHint):Builder.getLiteralString("");
      return Builder.createCallInst(CallInst::kNoTextifiedCallee,wrapper,
          Builder.getLiteralUndefined(),{hint});
    }
    if(name=="run_static_block") {
      if(op->_arguments.size()!=2) {
        Builder.getModule()->getContext().getSourceErrorManager().error(
            expr->getSourceRange(),"[NATIVE_CLASS_INVALID_IR] STATIC_BLOCK_ARITY");
        return Builder.getLiteralUndefined();
      }
      auto it=op->_arguments.begin();
      auto *fn=genExpression(&*it++);auto *receiver=genExpression(&*it);
      return Builder.createCallInst(CallInst::kNoTextifiedCallee,fn,receiver,{});
    }
    if(name=="set_super_literal_property") {
      if(op->_arguments.size()!=4){
        Builder.getModule()->getContext().getSourceErrorManager().error(expr->getSourceRange(),"[NATIVE_CLASS_INVALID_IR] SUPER_SET_ARITY");
        return Builder.getLiteralUndefined();
      }
      auto it=op->_arguments.begin();auto *receiver=genExpression(&*it++);
      auto *home=genExpression(&*it++);auto *key=genExpression(&*it++);auto *rhs=genExpression(&*it);
                                                                                 
                                                                             
      return genBuiltinCall(BuiltinMethod::HermesBuiltin_superPropertyGet,{home,key,receiver,rhs});
    }
    if(name=="get_super_property" || name=="call_super_property" ||
       name=="get_super_computed_property" || name=="call_super_computed_property") {
      const bool computed=name=="get_super_computed_property" || name=="call_super_computed_property";
      const bool invoke=name=="call_super_property" || name=="call_super_computed_property";
      if(op->_arguments.size()<3 || (!invoke && op->_arguments.size()!=3)) {
        Builder.getModule()->getContext().getSourceErrorManager().error(
            expr->getSourceRange(),"[NATIVE_CLASS_INVALID_IR] SUPER_PROPERTY_ARITY");
        return Builder.getLiteralUndefined();
      }
      auto it=op->_arguments.begin();
      auto *receiverNode=&*it++;
      auto *homeNode=&*it++;
      auto *keyNode=&*it++;
                                                                       
                                                                            
                                                                         
      auto *receiver=genExpression(receiverNode);
      auto *home=genExpression(homeNode);
      auto *key=genExpression(keyNode);
      if(computed)
        key=genBuiltinCall(BuiltinMethod::HermesBuiltin_classElementKey,{key});
      auto *value=genBuiltinCall(BuiltinMethod::HermesBuiltin_superPropertyGet,{home,key,receiver});
      if(!invoke)return value;
      bool spread=false;
      for(auto arg=it;arg!=op->_arguments.end();++arg)
        spread|=llvh::isa<ESTree::SpreadElementNode>(&*arg);
      if(spread) {
        ESTree::NodeList arguments;
        arguments.splice(arguments.end(),op->_arguments,it,op->_arguments.end());
        auto *array=genArrayFromElements(arguments);
        op->_arguments.splice(op->_arguments.end(),arguments);
        return genBuiltinCall(BuiltinMethod::HermesBuiltin_apply,{value,array,receiver});
      }
      CallInst::ArgumentList arguments;
      for(;it!=op->_arguments.end();++it)arguments.push_back(genExpression(&*it));
      return Builder.createCallInst(CallInst::kNoTextifiedCallee,value,receiver,arguments);
    }
    const bool derived = name == "init_derived";
    const bool heritage = name == "heritage_prototype";
    const bool initialize = name == "init_base";
    if (derived || heritage) {
      if (op->_arguments.size() != (derived ? 3u : 1u)) {
        Builder.getModule()->getContext().getSourceErrorManager().error(
            expr->getSourceRange(), "[NATIVE_DERIVED_INVALID_IR] DEFINITION_ARITY");
        return Builder.getLiteralUndefined();
      }
      llvh::SmallVector<Value *, 3> values;
      for (auto &argument : op->_arguments) values.push_back(genExpression(&argument));
      return genBuiltinCall(derived ? BuiltinMethod::HermesBuiltin_initDerivedClass
          : BuiltinMethod::HermesBuiltin_classHeritagePrototype, values);
    }
    const bool staticMethod = name == "define_static_method";
    const bool instanceGetter = name == "define_instance_getter";
    const bool instanceSetter = name == "define_instance_setter";
    const bool staticGetter = name == "define_static_getter";
    const bool staticSetter = name == "define_static_setter";
    const bool method = staticMethod || name == "define_instance_method" ||
        instanceGetter || instanceSetter || staticGetter || staticSetter;
    if ((!initialize && !method) ||
        op->_arguments.size() != (initialize ? 1u : 3u)) {
      Builder.getModule()->getContext().getSourceErrorManager().error(
          expr->getSourceRange(), "[NATIVE_CLASS_INVALID_IR] OPERATION_OR_ARITY");
      return Builder.getLiteralUndefined();
    }
    auto it = op->_arguments.begin();
    if (!llvh::isa<ESTree::IdentifierNode>(&*it)) {
      Builder.getModule()->getContext().getSourceErrorManager().error(
          expr->getSourceRange(), "[NATIVE_CLASS_INVALID_IR] CONSTRUCTOR_REFERENCE");
      return Builder.getLiteralUndefined();
    }
    if (method) {
      auto *key = &*++it;
      auto *function = llvh::dyn_cast<ESTree::FunctionExpressionNode>(&*++it);
      if (!(llvh::isa<ESTree::StringLiteralNode>(key) ||
            llvh::isa<ESTree::NumericLiteralNode>(key) || llvh::isa<ESTree::IdentifierNode>(key)) || !function ||
          function->loweredClassFunctionKind != ESTree::LoweredClassFunctionKind::Method ||
          (function->_async && (instanceGetter || instanceSetter ||
                               staticGetter || staticSetter)) ||
          (function->_generator && (!(staticMethod || name == "define_instance_method") || function->_async))) {
        Builder.getModule()->getContext().getSourceErrorManager().error(
            expr->getSourceRange(), "[NATIVE_CLASS_INVALID_IR] METHOD_OR_KEY");
        return Builder.getLiteralUndefined();
      }
    }
    llvh::SmallVector<Value *, 3> args;
    for (auto &arg : op->_arguments)
      args.push_back(genExpression(&arg));
    auto *definition = genBuiltinCall(
        initialize ? BuiltinMethod::HermesBuiltin_initBaseClass
        : instanceGetter ? BuiltinMethod::HermesBuiltin_defineInstanceClassGetter
        : instanceSetter ? BuiltinMethod::HermesBuiltin_defineInstanceClassSetter
        : staticGetter ? BuiltinMethod::HermesBuiltin_defineStaticClassGetter
        : staticSetter ? BuiltinMethod::HermesBuiltin_defineStaticClassSetter
        : staticMethod ? BuiltinMethod::HermesBuiltin_defineStaticClassMethod
                       : BuiltinMethod::HermesBuiltin_defineInstanceClassMethod,
        args);
                                                                            
                                                                            
    return definition;
  }

                                                                             
  if (auto *op = llvh::dyn_cast<ESTree::NativePublicFieldOperationNode>(expr)) {
    const auto name = op->_operation->str();
    if(name=="to_key" || name=="named_function_dynamic") {
      const bool naming=name=="named_function_dynamic";
      if(op->_arguments.size()!=(naming?2u:1u)) {
        Builder.getModule()->getContext().getSourceErrorManager().error(
            expr->getSourceRange(),"[NATIVE_PUBLIC_FIELD_INVALID_IR] KEY_OPERATION_ARITY");
        return Builder.getLiteralUndefined();
      }
      llvh::SmallVector<Value *,2> args;
      for(auto &arg:op->_arguments)args.push_back(genExpression(&arg));
      return genBuiltinCall(naming?BuiltinMethod::HermesBuiltin_namePublicFieldFunction
          :BuiltinMethod::HermesBuiltin_classElementKey,args);
    }
    if(name=="named_function") {
      if(op->_arguments.size()!=2) {
        Builder.getModule()->getContext().getSourceErrorManager().error(
            expr->getSourceRange(),"[NATIVE_PUBLIC_FIELD_INVALID_IR] FUNCTION_NAME_ARITY");
        return Builder.getLiteralUndefined();
      }
      auto it=op->_arguments.begin();auto *key=&*it++;auto *value=&*it;
      auto *fn=llvh::dyn_cast<ESTree::FunctionExpressionNode>(value);
      if(!(llvh::isa<ESTree::StringLiteralNode>(key)||llvh::isa<ESTree::NumericLiteralNode>(key))||
         !(llvh::isa<ESTree::ArrowFunctionExpressionNode>(value)||(fn&&!fn->_id))) {
        Builder.getModule()->getContext().getSourceErrorManager().error(
            expr->getSourceRange(),"[NATIVE_PUBLIC_FIELD_INVALID_IR] FUNCTION_NAME_OPERANDS");
        return Builder.getLiteralUndefined();
      }
      llvh::SmallVector<char,32> storage;
      return genExpression(value,Builder.createIdentifier(propertyKeyAsString(storage,key)));
    }
    const unsigned arity = name == "evaluate" ? 2
        : (name == "define" || name == "define_instance") ? 3 : 0;
    if (!arity || op->_arguments.size() != arity) {
      Builder.getModule()->getContext().getSourceErrorManager().error(
          expr->getSourceRange(), "[NATIVE_PUBLIC_FIELD_INVALID_IR] OPERATION_OR_ARITY");
      return Builder.getLiteralUndefined();
    }
    if (name == "evaluate") {
      auto it = op->_arguments.begin();
      Value *closure = genExpression(&*it++);
      Value *receiver = genExpression(&*it);
      CallInst::ArgumentList noArguments;
                                                                              
                                                                                   
      return Builder.createCallInst(CallInst::kNoTextifiedCallee,
          closure, receiver, noArguments);
    }
    if (name=="define_instance" &&
        !llvh::isa<ESTree::ThisExpressionNode>(&op->_arguments.front())) {
      Builder.getModule()->getContext().getSourceErrorManager().error(
          expr->getSourceRange(), "[NATIVE_PUBLIC_FIELD_INVALID_IR] INSTANCE_RECEIVER");
      return Builder.getLiteralUndefined();
    }
                                                                               
                                                                    
    auto key = op->_arguments.begin();
    ++key;
    if (!llvh::isa<ESTree::StringLiteralNode>(&*key) &&
        !llvh::isa<ESTree::NumericLiteralNode>(&*key) && !llvh::isa<ESTree::IdentifierNode>(&*key)) {
      Builder.getModule()->getContext().getSourceErrorManager().error(
          expr->getSourceRange(), "[NATIVE_PUBLIC_FIELD_INVALID_IR] NONLITERAL_KEY");
      return Builder.getLiteralUndefined();
    }
    llvh::SmallVector<Value *, 3> args;
    for (auto &arg : op->_arguments)
      args.push_back(genExpression(&arg));
                                                                          
                                                                              
    return genBuiltinCall(name=="define_instance"
        ? BuiltinMethod::HermesBuiltin_definePublicInstanceClassField
        : BuiltinMethod::HermesBuiltin_definePublicClassField, args);
  }

                                                                           
                                                                           
  if (auto *op = llvh::dyn_cast<ESTree::NativePrivateOperationNode>(expr)) {
    auto name=op->_operation->str();
    if(name=="add_field"||name=="add_accessor"||name=="add_readonly"||
       name=="multiply_field"||name=="multiply_accessor"||name=="multiply_readonly") {
      const bool multiply=name.startswith("multiply_");
      const bool accessor=name=="add_accessor"||name=="multiply_accessor",readonly=name=="add_readonly"||name=="multiply_readonly";
      if(op->_arguments.size()!=(accessor?4u:3u)) {
        Builder.getModule()->getContext().getSourceErrorManager().error(expr->getSourceRange(),"[NATIVE_PRIVATE_INVALID_IR] ADD_ARITY");
        return Builder.getLiteralUndefined();
      }
      auto it=op->_arguments.begin();auto *receiver=genExpression(&*it++);auto *token=genExpression(&*it++);
      auto *old=genBuiltinCall(BuiltinMethod::HermesBuiltin_privateFieldGet,{receiver,token});
      if(accessor)old=Builder.createCallInst(CallInst::kNoTextifiedCallee,old,receiver,{});
      ESTree::Node *setterNode=accessor?&*it++:nullptr;
      auto *rhs=genExpression(&*it);
                                                                                
      auto *next=Builder.createBinaryOperatorInst(old,rhs,multiply?BinaryOperatorInst::OpKind::MultiplyKind:BinaryOperatorInst::OpKind::AddKind);
      if(readonly)genBuiltinCall(BuiltinMethod::HermesBuiltin_throwTypeError,{Builder.getLiteralString("Cannot assign private method")});
      else if(accessor){
        auto *setterToken=genExpression(setterNode);
        auto *setter=genBuiltinCall(BuiltinMethod::HermesBuiltin_privateFieldGet,{receiver,setterToken});
        Builder.createCallInst(CallInst::kNoTextifiedCallee,setter,receiver,{next});
      }else genBuiltinCall(BuiltinMethod::HermesBuiltin_privateFieldSet,{receiver,token,next});
      return next;
    }
    if(name.startswith("update_")) {
      const bool accessor=name.startswith("update_accessor_");
      const bool readonly=name.startswith("update_readonly_");
      const bool increment=name.contains("_inc_");
      const bool prefix=name.endswith("_prefix");
      if(op->_arguments.size()!=(accessor?3u:2u)) {
        Builder.getModule()->getContext().getSourceErrorManager().error(
            expr->getSourceRange(),"[NATIVE_PRIVATE_INVALID_IR] UPDATE_ARITY");
        return Builder.getLiteralUndefined();
      }
      auto it=op->_arguments.begin();
      Value *receiver=genExpression(&*it++),*token=genExpression(&*it++);
      Value *old=genBuiltinCall(BuiltinMethod::HermesBuiltin_privateFieldGet,{receiver,token});
      if(accessor)old=Builder.createCallInst(CallInst::kNoTextifiedCallee,old,receiver,{});
                                                                              
      old=Builder.createAsNumericInst(old);
      auto *next=Builder.createUnaryOperatorInst(old,increment?
          UnaryOperatorInst::OpKind::IncKind:UnaryOperatorInst::OpKind::DecKind);
      if(readonly)genBuiltinCall(BuiltinMethod::HermesBuiltin_throwTypeError,
          {Builder.getLiteralString("Private method is not writable")});
      else if(accessor) {
        auto *setterToken=genExpression(&*it);
        auto *setter=genBuiltinCall(BuiltinMethod::HermesBuiltin_privateFieldGet,{receiver,setterToken});
        Builder.createCallInst(CallInst::kNoTextifiedCallee,setter,receiver,{next});
      } else genBuiltinCall(BuiltinMethod::HermesBuiltin_privateFieldSet,{receiver,token,next});
      return prefix?next:old;
    }
    if (name=="evaluate") {
      if (op->_arguments.size()!=2) {
        Builder.getModule()->getContext().getSourceErrorManager().error(
            expr->getSourceRange(),"[NATIVE_PRIVATE_INVALID_IR] INITIALIZER_CALL_ARITY");
        return Builder.getLiteralUndefined();
      }
      auto it=op->_arguments.begin();
      Value *closure=genExpression(&*it++);
      Value *receiver=genExpression(&*it);
      CallInst::ArgumentList noArguments;
                                                                         
      return Builder.createCallInst(CallInst::kNoTextifiedCallee,
          closure,receiver,noArguments);
    }
    if(name=="call" || name=="accessor_call" || name=="accessor_get" ||
       name=="accessor_set" || name=="readonly_set") {
      const bool calling=name=="call" || name=="accessor_call";
      const bool writing=name=="accessor_set" || name=="readonly_set";
      if(op->_arguments.size()<2 || (!calling && op->_arguments.size()!=(writing?3u:2u))) {
        Builder.getModule()->getContext().getSourceErrorManager().error(
            expr->getSourceRange(),"[NATIVE_PRIVATE_INVALID_IR] MEMBER_ARITY");
        return Builder.getLiteralUndefined();
      }
      auto it=op->_arguments.begin();
      Value *receiver=genExpression(&*it++);
      Value *token=genExpression(&*it++);
                                                                              
                                                                            
      Value *rhs=writing?genExpression(&*it++):nullptr;
      Value *fn=genBuiltinCall(BuiltinMethod::HermesBuiltin_privateFieldGet,{receiver,token});
      CallInst::ArgumentList args;
      if(name=="readonly_set")
        return genBuiltinCall(BuiltinMethod::HermesBuiltin_throwTypeError,
            {Builder.getLiteralString("Private method is not writable")});
      if(name=="accessor_get" || name=="accessor_call") {
        fn=Builder.createCallInst(CallInst::kNoTextifiedCallee,fn,receiver,args);
        if(name=="accessor_get")return fn;
      }
      if(writing)args.push_back(rhs);
      else for(;it!=op->_arguments.end();++it)args.push_back(genExpression(&*it));
      Value *result=Builder.createCallInst(CallInst::kNoTextifiedCallee,fn,receiver,args);
      return writing?rhs:result;
    }
    BuiltinMethod::Enum builtin;
    unsigned expected;
    if (name=="create") { builtin=BuiltinMethod::HermesBuiltin_privateNameCreate;expected=0; }
    else if (name=="init" || name=="init_member") { builtin=BuiltinMethod::HermesBuiltin_privateFieldInit;expected=3; }
    else if (name=="get") { builtin=BuiltinMethod::HermesBuiltin_privateFieldGet;expected=2; }
    else if (name=="set") { builtin=BuiltinMethod::HermesBuiltin_privateFieldSet;expected=3; }
    else {
      Builder.getModule()->getContext().getSourceErrorManager().error(
          expr->getSourceRange(), "[NATIVE_PRIVATE_INVALID_IR] UNKNOWN_OPERATION");
      return Builder.getLiteralUndefined();
    }
    if (op->_arguments.size()!=expected) {
      Builder.getModule()->getContext().getSourceErrorManager().error(
          expr->getSourceRange(), "[NATIVE_PRIVATE_INVALID_IR] OPERAND_ARITY");
      return Builder.getLiteralUndefined();
    }
    llvh::SmallVector<Value *,3> args;
    for (auto &arg:op->_arguments) args.push_back(genExpression(&arg));
    return genBuiltinCall(builtin,args);
  }

                        
  if (auto *Iden = llvh::dyn_cast<ESTree::IdentifierNode>(expr)) {
    return genIdentifierExpression(Iden, false);
  }

                          
                                                                      
  if (llvh::isa<ESTree::NullLiteralNode>(expr)) {
    return Builder.getLiteralNull();
  }

                            
                                                                                 
  if (auto *Lit = llvh::dyn_cast<ESTree::StringLiteralNode>(expr)) {
    LLVM_DEBUG(
        llvh::dbgs() << "Loading String Literal \"" << Lit->_value << "\"\n");
    return Builder.getLiteralString(Lit->_value->str());
  }

                            
                                                                                             
  if (auto *Lit = llvh::dyn_cast<ESTree::RegExpLiteralNode>(expr)) {
    return genRegExpLiteral(Lit);
  }

                             
                                                                         
  if (auto *Lit = llvh::dyn_cast<ESTree::BooleanLiteralNode>(expr)) {
    LLVM_DEBUG(
        llvh::dbgs() << "Loading String Literal \"" << Lit->_value << "\"\n");
    return Builder.getLiteralBool(Lit->_value);
  }

                            
                                                                                  
  if (auto *Lit = llvh::dyn_cast<ESTree::NumericLiteralNode>(expr)) {
    LLVM_DEBUG(
        llvh::dbgs() << "Loading Numeric Literal \"" << Lit->_value << "\"\n");
    return Builder.getLiteralNumber(Lit->_value);
  }

                            
                                                                                  
  if (auto *Lit = llvh::dyn_cast<ESTree::BigIntLiteralNode>(expr)) {
    LLVM_DEBUG(
        llvh::dbgs() << "Loading BitInt Literal \"" << Lit->_bigint->str()
                     << "\"\n");
    return Builder.getLiteralBigInt(Lit->_bigint);
  }

                                      
  if (auto Assign = llvh::dyn_cast<ESTree::AssignmentExpressionNode>(expr)) {
    return genAssignmentExpr(Assign);
  }

                             
  if (auto *call = llvh::dyn_cast<ESTree::CallExpressionNode>(expr)) {
    return genCallExpr(call);
  }

                             
  if (auto *call = llvh::dyn_cast<ESTree::OptionalCallExpressionNode>(expr)) {
    return genOptionalCallExpr(call, nullptr);
  }

                                  
  if (auto *newExp = llvh::dyn_cast<ESTree::NewExpressionNode>(expr)) {
    return genNewExpr(newExp);
  }

                                                             
  if (auto *Mem = llvh::dyn_cast<ESTree::MemberExpressionNode>(expr)) {
    return genMemberExpression(Mem, MemberExpressionOperation::Load).result;
  }

                                                             
  if (auto *mem = llvh::dyn_cast<ESTree::OptionalMemberExpressionNode>(expr)) {
    return genOptionalMemberExpression(
               mem, nullptr, MemberExpressionOperation::Load)
        .result;
  }

                                                
  if (auto *Arr = llvh::dyn_cast<ESTree::ArrayExpressionNode>(expr)) {
    return genArrayExpr(Arr);
  }

                                                     
  if (auto *Obj = llvh::dyn_cast<ESTree::ObjectExpressionNode>(expr)) {
    return genObjectExpr(Obj);
  }

                                                   
  if (auto *L = llvh::dyn_cast<ESTree::LogicalExpressionNode>(expr)) {
    return genLogicalExpression(L);
  }

                               
  if (auto *Bin = llvh::dyn_cast<ESTree::BinaryExpressionNode>(expr)) {
    return genBinaryExpression(Bin);
  }

                                       
  if (auto *U = llvh::dyn_cast<ESTree::UnaryExpressionNode>(expr)) {
    return genUnaryExpression(U);
  }

                               
  if (llvh::isa<ESTree::ThisExpressionNode>(expr)) {
    if (curFunction()->derivedThis)
      return genBuiltinCall(BuiltinMethod::HermesBuiltin_assertDerivedThis,
          {Builder.createLoadFrameInst(curFunction()->derivedThis, currentIRScope_)});
    if (curFunction()->function->getDefinitionKind() ==
        Function::DefinitionKind::ES6Arrow) {
      assert(
          curFunction()->capturedThis &&
          "arrow function must have a captured this");
      return Builder.createLoadFrameInst(
          curFunction()->capturedThis, currentIRScope_);
    }
    return curFunction()->function->getThisParameter();
  }

  if (auto *MP = llvh::dyn_cast<ESTree::MetaPropertyNode>(expr)) {
    return genMetaProperty(MP);
  }

                                 
  if (auto *FE = llvh::dyn_cast<ESTree::FunctionExpressionNode>(expr)) {
    return genFunctionExpression(FE, nameHint);
  }

  if (auto *AF = llvh::dyn_cast<ESTree::ArrowFunctionExpressionNode>(expr)) {
    return genArrowFunctionExpression(AF, nameHint);
  }

  if (auto *U = llvh::dyn_cast<ESTree::UpdateExpressionNode>(expr)) {
    return genUpdateExpr(U);
  }

  if (auto *C = llvh::dyn_cast<ESTree::ConditionalExpressionNode>(expr)) {
    return genConditionalExpr(C);
  }

  if (auto *Sq = llvh::dyn_cast<ESTree::SequenceExpressionNode>(expr)) {
    return genSequenceExpr(Sq);
  }

  if (auto *Tl = llvh::dyn_cast<ESTree::TemplateLiteralNode>(expr)) {
    return genTemplateLiteralExpr(Tl);
  }

  if (auto *Tt = llvh::dyn_cast<ESTree::TaggedTemplateExpressionNode>(expr)) {
    return genTaggedTemplateExpr(Tt);
  }

  if (auto *Y = llvh::dyn_cast<ESTree::YieldExpressionNode>(expr)) {
    return Y->_delegate ? genYieldStarExpr(Y) : genYieldExpr(Y);
  }

  if (auto *A = llvh::dyn_cast<ESTree::AwaitExpressionNode>(expr)) {
    return genAwaitExpr(A);
  }

  Builder.getModule()->getContext().getSourceErrorManager().error(
      expr->getSourceRange(),
      Twine("Invalid expression encountered AST=") + expr->getNodeName());
  return Builder.getLiteralUndefined();
}

void ESTreeIRGen::genExpressionBranch(
    ESTree::Node *expr,
    BasicBlock *onTrue,
    BasicBlock *onFalse,
    BasicBlock *onNullish) {
  switch (expr->getKind()) {
    case ESTree::NodeKind::LogicalExpression:
      return genLogicalExpressionBranch(
          cast<ESTree::LogicalExpressionNode>(expr),
          onTrue,
          onFalse,
          onNullish);

    case ESTree::NodeKind::UnaryExpression: {
      auto *e = cast<ESTree::UnaryExpressionNode>(expr);
      switch (UnaryOperatorInst::parseOperator(e->_operator->str())) {
        case UnaryOperatorInst::OpKind::BangKind:
                                                                             
          return genExpressionBranch(e->_argument, onFalse, onTrue, nullptr);
        default:
          break;
      }

      break;
    }

    case ESTree::NodeKind::SequenceExpression: {
      auto *e = cast<ESTree::SequenceExpressionNode>(expr);

      ESTree::NodePtr last = nullptr;
      for (auto &ex : e->_expressions) {
        if (last)
          genExpression(last);
        last = &ex;
      }
      if (last)
        genExpressionBranch(last, onTrue, onFalse, onNullish);
      return;
    }

    default:
      break;
  }

  Value *condVal = genExpression(expr);
  if (onNullish) {
    Value *isNullish = Builder.createBinaryOperatorInst(
        condVal,
        Builder.getLiteralNull(),
        BinaryOperatorInst::OpKind::EqualKind);
    BasicBlock *notNullishBB = Builder.createBasicBlock(Builder.getFunction());
    Builder.createCondBranchInst(isNullish, onNullish, notNullishBB);
    Builder.setInsertionBlock(notNullishBB);
  }
  Builder.createCondBranchInst(condVal, onTrue, onFalse);
}

Value *ESTreeIRGen::genArrayFromElements(ESTree::NodeList &list) {
  LLVM_DEBUG(llvh::dbgs() << "Initializing a new array\n");
  AllocArrayInst::ArrayValueList elements;

                                                                        
                                                                               
                                                                           
  unsigned minElements = 0;
  bool variableLength = false;
  for (auto &E : list) {
    if (llvh::isa<ESTree::SpreadElementNode>(&E)) {
      variableLength = true;
      continue;
    }
    ++minElements;
  }

                                                              
                                                           
                                                                  

                                                                        
                                                                         
                                                          
  unsigned count = 0;
  AllocStackInst *nextIndex = nullptr;
  if (variableLength) {
                                                                        
                                               
    nextIndex = Builder.createAllocStackInst("nextIndex");
    Builder.createStoreStackInst(Builder.getLiteralPositiveZero(), nextIndex);
  }

  bool consecutive = true;
  auto codeGenOpts = Mod->getContext().getCodeGenerationSettings();
  AllocArrayInst *allocArrayInst = nullptr;
  for (auto &E : list) {
    Value *value{nullptr};
    bool isSpread = false;
    if (!llvh::isa<ESTree::EmptyNode>(&E)) {
      if (auto *spread = llvh::dyn_cast<ESTree::SpreadElementNode>(&E)) {
        isSpread = true;
        value = genExpression(spread->_argument);
      } else {
        value = genExpression(&E);
      }
    }
    if (!value ||
        (!llvh::isa<Literal>(value) && !codeGenOpts.unlimitedRegisters) ||
        isSpread) {
                                   
                                                   
                             
      if (consecutive) {
                                                              
                                                     
        allocArrayInst = Builder.createAllocArrayInst(elements, minElements);
        consecutive = false;
      }
    }
    if (isSpread) {
                                                          
                                                                       
                                                                               
      auto *newNextIndex = genBuiltinCall(
          BuiltinMethod::HermesBuiltin_arraySpread,
          {allocArrayInst, value, Builder.createLoadStackInst(nextIndex)});
      Builder.createStoreStackInst(newNextIndex, nextIndex);
      continue;
    }
                                                                      
    if (value) {
      if (consecutive) {
        elements.push_back(value);
      } else {
        Builder.createStoreOwnPropertyInst(
            value,
            allocArrayInst,
            variableLength ? cast<Value>(Builder.createLoadStackInst(nextIndex))
                           : cast<Value>(Builder.getLiteralNumber(count)),
            IRBuilder::PropEnumerable::Yes);
      }
    }
                                                                                
             
    if (variableLength) {
                                                                               
                                                                         
                                                                          
      Builder.createStoreStackInst(
          Builder.createBinaryOperatorInst(
              Builder.createLoadStackInst(nextIndex),
              Builder.getLiteralNumber(1),
              BinaryOperatorInst::OpKind::AddKind),
          nextIndex);
    } else {
      count++;
    }
  }

  if (!allocArrayInst) {
    assert(
        !variableLength &&
        "variable length arrays must allocate their own arrays");
    allocArrayInst = Builder.createAllocArrayInst(elements, list.size());
  }
  if (!list.empty() && llvh::isa<ESTree::EmptyNode>(&list.back())) {
                                                                        
                                    
    Value *newLength;
    if (variableLength)
      newLength = Builder.createLoadStackInst(nextIndex);
    else
      newLength = Builder.getLiteralNumber(count);
    Builder.createStorePropertyInst(
        newLength, allocArrayInst, llvh::StringRef("length"));
  }
  return allocArrayInst;
}

Value *ESTreeIRGen::genArrayExpr(ESTree::ArrayExpressionNode *Expr) {
  return genArrayFromElements(Expr->_elements);
}

Value *ESTreeIRGen::genCallExpr(ESTree::CallExpressionNode *call) {
  LLVM_DEBUG(llvh::dbgs() << "IRGen 'call' statement/expression.\n");

                                       
  if (auto *identNode = llvh::dyn_cast<ESTree::IdentifierNode>(call->_callee)) {
    if (Identifier::getFromPointer(identNode->_name) == identEval_) {
      auto *evalVar = nameTable_.lookup(identEval_);
      if (!evalVar || llvh::isa<GlobalObjectProperty>(evalVar))
        return genCallEvalExpr(call);
    }
  }

  Value *thisVal;
  Value *callee;

                                                                            
  if (auto *Mem = llvh::dyn_cast<ESTree::MemberExpressionNode>(call->_callee)) {
    MemberExpressionResult memResult =
        genMemberExpression(Mem, MemberExpressionOperation::Load);

                                                      
    thisVal = memResult.base;
    callee = memResult.result;
  } else if (
      auto *Mem =
          llvh::dyn_cast<ESTree::OptionalMemberExpressionNode>(call->_callee)) {
    MemberExpressionResult memResult = genOptionalMemberExpression(
        Mem, nullptr, MemberExpressionOperation::Load);

                                                      
    thisVal = memResult.base;
    callee = memResult.result;
  } else {
    thisVal = Builder.getLiteralUndefined();
    callee = genExpression(call->_callee);
  }

  return emitCall(call, callee, thisVal);
}

Value *ESTreeIRGen::genOptionalCallExpr(
    ESTree::OptionalCallExpressionNode *call,
    BasicBlock *shortCircuitBB) {
  PhiInst::ValueListType values;
  PhiInst::BasicBlockListType blocks;

                                                              
                                  
  bool isFirstOptional = shortCircuitBB == nullptr;

                                                                            
              
  BasicBlock *continueBB = nullptr;

  if (!shortCircuitBB) {
                                                                            
                                                                          
                                                                        
    continueBB = Builder.createBasicBlock(Builder.getFunction());
    auto *insertionBB = Builder.getInsertionBlock();
    shortCircuitBB = Builder.createBasicBlock(Builder.getFunction());
    Builder.setInsertionBlock(shortCircuitBB);
    values.push_back(Builder.getLiteralUndefined());
    blocks.push_back(shortCircuitBB);
    Builder.createBranchInst(continueBB);
    Builder.setInsertionBlock(insertionBB);
  }

  Value *thisVal;
  Value *callee;

                                                                            
  if (auto *me = llvh::dyn_cast<ESTree::MemberExpressionNode>(call->_callee)) {
    MemberExpressionResult memResult =
        genMemberExpression(me, MemberExpressionOperation::Load);

                                                      
    thisVal = memResult.base;
    callee = memResult.result;
  } else if (
      auto *ome =
          llvh::dyn_cast<ESTree::OptionalMemberExpressionNode>(call->_callee)) {
    MemberExpressionResult memResult = genOptionalMemberExpression(
        ome, shortCircuitBB, MemberExpressionOperation::Load);

                                                      
    thisVal = memResult.base;
    callee = memResult.result;
  } else if (
      auto *oce =
          llvh::dyn_cast<ESTree::OptionalCallExpressionNode>(call->_callee)) {
    thisVal = Builder.getLiteralUndefined();
    callee = genOptionalCallExpr(oce, shortCircuitBB);
  } else if (auto *op = llvh::dyn_cast<ESTree::NativePrivateOperationNode>(call->_callee)) {
    const auto name=op->_operation->str();
    if((name!="call_reference" && name!="accessor_call_reference") || op->_arguments.size()!=2) {
      Builder.getModule()->getContext().getSourceErrorManager().error(
          call->getSourceRange(),"[NATIVE_PRIVATE_INVALID_IR] OPTIONAL_REFERENCE");
      return Builder.getLiteralUndefined();
    }
    auto it=op->_arguments.begin();
    thisVal=genExpression(&*it++);
    Value *token=genExpression(&*it);
                                                                              
    callee=genBuiltinCall(BuiltinMethod::HermesBuiltin_privateFieldGet,{thisVal,token});
    if(name=="accessor_call_reference") {
      CallInst::ArgumentList noArguments;
      callee=Builder.createCallInst(CallInst::kNoTextifiedCallee,callee,thisVal,noArguments);
    }
  } else {
    thisVal = Builder.getLiteralUndefined();
    callee = genExpression(getCallee(call));
  }

  if (call->_optional) {
    BasicBlock *evalRHSBB = Builder.createBasicBlock(Builder.getFunction());

                                                             
                                                                         
    Builder.createCondBranchInst(
        Builder.createBinaryOperatorInst(
            callee,
            Builder.getLiteralNull(),
            BinaryOperatorInst::OpKind::EqualKind),
        shortCircuitBB,
        evalRHSBB);

                                          
    Builder.setInsertionBlock(evalRHSBB);
  }

  Value *callResult = emitCall(call, callee, thisVal);

  if (isFirstOptional) {
    values.push_back(callResult);
    blocks.push_back(Builder.getInsertionBlock());
    Builder.createBranchInst(continueBB);

    Builder.setInsertionBlock(continueBB);
    return Builder.createPhiInst(values, blocks);
  }

                                                                     
                
  return callResult;
}

                                                                          
                                                                                
                 
   
                                                                               
               
                                                                                
                                                                             
                  
   
                                               
                                                  
static LiteralString *getTextifiedCallExpr(
    IRBuilder &builder,
    ESTree::Node *callee) {
  constexpr uint32_t kMaxTextifiedCalleeSizeUTF8Chars = 64;
                                                                           
                             
  llvh::SmallVector<char, kMaxTextifiedCalleeSizeUTF8Chars * 4> textifiedCallee;
  llvh::raw_svector_ostream OS(textifiedCallee);

                                                                         
  uint32_t numUTF8Chars = 0;
  const char *begin = callee->getSourceRange().Start.getPointer();
  const char *end = callee->getSourceRange().End.getPointer();

  const char *pos = begin;

                                                                             
                                                                            
                                                                         
                                                                           
                              
  auto nextUTF8Char = [end](const char *&iter) -> OptValue<llvh::StringRef> {
    assert(iter < end && "iter is past end");
    const char *start;
    bool skipSpace = false;
    bool newLine;
    bool unprintableChar;
                                                                                
                                                              
    do {
      if (iter == end) {
        return llvh::None;
      }

                                                                
      start = iter;
      for (++iter; iter < end && isUTF8ContinuationByte(*iter); ++iter) {
                  
      }

      newLine = *start == '\n';
      skipSpace |= newLine;
      unprintableChar = static_cast<uint8_t>(*start) < 32;
    } while (unprintableChar || newLine || (skipSpace && *start == ' '));

    const size_t utf8CharLength = static_cast<size_t>(iter - start);
    return llvh::StringRef{start, utf8CharLength};
  };

                                                    
                                                                              
                                                             
                                                                              
                                                                                
                                   
                                                                     
    
                                                                               
                                                                              
                                                                  
                                                                             
                                                                      

                                                                             
                                                    
  while (pos < end && numUTF8Chars < kMaxTextifiedCalleeSizeUTF8Chars / 2) {
    if (auto ch = nextUTF8Char(pos)) {
      ++numUTF8Chars;
      OS << *ch;
    }
  }

  assert(
      (pos == end || numUTF8Chars == kMaxTextifiedCalleeSizeUTF8Chars / 2) &&
      "Invalid source range");

                                                                               
                                               
  const char *mark = pos;
  while (pos < end && numUTF8Chars < kMaxTextifiedCalleeSizeUTF8Chars) {
    if (nextUTF8Char(pos)) {
      ++numUTF8Chars;
    }
  }

  assert(
      (pos == end || numUTF8Chars == kMaxTextifiedCalleeSizeUTF8Chars) &&
      "Invalid source range");

  if (pos < end) {
                                                                     
    OS << "(...)";

    while (pos < end) {
      auto ch = nextUTF8Char(mark);
      assert(ch && "should have a character");
      (void)ch;
      nextUTF8Char(pos);
    }
  }

                                                                            
                                              
  assert(pos == end && "Invalid source range");

                                                                           
  while (mark < end) {
    auto ch = nextUTF8Char(mark);
    assert(ch && "should have a character");
    OS << *ch;
  }

  return builder.getLiteralString(OS.str());
}

Value *ESTreeIRGen::emitCall(
    ESTree::CallExpressionLikeNode *call,
    Value *callee,
    Value *thisVal) {
  bool hasSpread = false;
  for (auto &arg : getArguments(call)) {
    if (llvh::isa<ESTree::SpreadElementNode>(&arg)) {
      hasSpread = true;
    }
  }

  if (!hasSpread) {
    CallInst::ArgumentList args;
    for (auto &arg : getArguments(call)) {
      args.push_back(genExpression(&arg));
    }

    return Builder.createCallInst(
        getTextifiedCallExpr(Builder, getCallee(call)), callee, thisVal, args);
  }

                                                                          
                 
                                                                         
                                                  
  auto *args = genArrayFromElements(getArguments(call));
  return genBuiltinCall(
      BuiltinMethod::HermesBuiltin_apply, {callee, args, thisVal});
}

ESTreeIRGen::MemberExpressionResult ESTreeIRGen::genMemberExpression(
    ESTree::MemberExpressionNode *mem,
    MemberExpressionOperation op) {
  Value *baseValue = genExpression(mem->_object);
  Value *prop = genMemberExpressionProperty(mem);
  switch (op) {
    case MemberExpressionOperation::Load:
      return MemberExpressionResult{
          Builder.createLoadPropertyInst(baseValue, prop), baseValue};
    case MemberExpressionOperation::Delete:
      return MemberExpressionResult{
          Builder.createDeletePropertyInst(baseValue, prop), baseValue};
  }
  llvm_unreachable("No other kind of member expression");
}

ESTreeIRGen::MemberExpressionResult ESTreeIRGen::genOptionalMemberExpression(
    ESTree::OptionalMemberExpressionNode *mem,
    BasicBlock *shortCircuitBB,
    MemberExpressionOperation op) {
  PhiInst::ValueListType values;
  PhiInst::BasicBlockListType blocks;

                                                                      
                                  
  bool isFirstOptional = shortCircuitBB == nullptr;

                                                                            
              
  BasicBlock *continueBB = nullptr;

  if (isFirstOptional) {
                                                                            
                                                                          
                                                                        
    continueBB = Builder.createBasicBlock(Builder.getFunction());
    auto *insertionBB = Builder.getInsertionBlock();
    shortCircuitBB = Builder.createBasicBlock(Builder.getFunction());
    Builder.setInsertionBlock(shortCircuitBB);
    values.push_back(Builder.getLiteralUndefined());
    blocks.push_back(shortCircuitBB);
    Builder.createBranchInst(continueBB);
    Builder.setInsertionBlock(insertionBB);
  }

  Value *baseValue = nullptr;
  if (ESTree::OptionalMemberExpressionNode *ome =
          llvh::dyn_cast<ESTree::OptionalMemberExpressionNode>(mem->_object)) {
    baseValue = genOptionalMemberExpression(
                    ome, shortCircuitBB, MemberExpressionOperation::Load)
                    .result;
  } else if (
      ESTree::OptionalCallExpressionNode *oce =
          llvh::dyn_cast<ESTree::OptionalCallExpressionNode>(mem->_object)) {
    baseValue = genOptionalCallExpr(oce, shortCircuitBB);
  } else {
    baseValue = genExpression(mem->_object);
  }

  if (mem->_optional) {
    BasicBlock *evalRHSBB = Builder.createBasicBlock(Builder.getFunction());

                                                                
                                                                         
    Builder.createCondBranchInst(
        Builder.createBinaryOperatorInst(
            baseValue,
            Builder.getLiteralNull(),
            BinaryOperatorInst::OpKind::EqualKind),
        shortCircuitBB,
        evalRHSBB);

                                                                 
    Builder.setInsertionBlock(evalRHSBB);
  }

  Value *prop = genMemberExpressionProperty(mem);
  Value *result = nullptr;
  switch (op) {
    case MemberExpressionOperation::Load:
      result = Builder.createLoadPropertyInst(baseValue, prop);
      break;
    case MemberExpressionOperation::Delete:
      result = Builder.createDeletePropertyInst(baseValue, prop);
      break;
  }
  assert(result && "result must be set");

  if (isFirstOptional) {
    values.push_back(result);
    blocks.push_back(Builder.getInsertionBlock());
    Builder.createBranchInst(continueBB);

    Builder.setInsertionBlock(continueBB);
    return {Builder.createPhiInst(values, blocks), baseValue};
  }

                                                                             
  return {result, baseValue};
}

Value *ESTreeIRGen::genCallEvalExpr(ESTree::CallExpressionNode *call) {
  if (call->_arguments.empty()) {
    Mod->getContext().getSourceErrorManager().warning(
        call->getSourceRange(), "eval() without arguments returns undefined");
    return Builder.getLiteralUndefined();
  }

  Mod->getContext().getSourceErrorManager().warning(
      Warning::DirectEval,
      call->getSourceRange(),
      "Direct call to eval(), but lexical scope is not supported.");

  llvh::SmallVector<Value *, 1> args;
  for (auto &arg : call->_arguments) {
    args.push_back(genExpression(&arg));
  }

  if (args.size() > 1) {
    Mod->getContext().getSourceErrorManager().warning(
        call->getSourceRange(), "Extra eval() arguments are ignored");
  }

  bool isStrict = Builder.getInsertionBlock()->getParent()->isStrictMode();
  return Builder.createDirectEvalInst(
      args[0], Builder.getLiteralBool(isStrict));
}

                                                                        
static llvh::StringRef propertyKeyAsString(
    llvh::SmallVectorImpl<char> &storage,
    ESTree::Node *Key) {
                            
                                                                                 
  if (auto *Lit = llvh::dyn_cast<ESTree::StringLiteralNode>(Key)) {
    LLVM_DEBUG(
        llvh::dbgs() << "Loading String Literal \"" << Lit->_value << "\"\n");
    return Lit->_value->str();
  }

                                                       
  if (auto *Iden = llvh::dyn_cast<ESTree::IdentifierNode>(Key)) {
    LLVM_DEBUG(
        llvh::dbgs() << "Loading String Literal \"" << Iden->_name << "\"\n");
    return Iden->_name->str();
  }

                            
                                                                                  
  if (auto *Lit = llvh::dyn_cast<ESTree::NumericLiteralNode>(Key)) {
    LLVM_DEBUG(
        llvh::dbgs() << "Loading Numeric Literal \"" << Lit->_value << "\"\n");
    storage.resize(NUMBER_TO_STRING_BUF_SIZE);
    auto len = numberToString(Lit->_value, storage.data(), storage.size());
    return llvh::StringRef(storage.begin(), len);
  }

  llvm_unreachable("Don't know this kind of property key");
  return llvh::StringRef();
}

Value *ESTreeIRGen::genObjectExpr(ESTree::ObjectExpressionNode *Expr) {
  LLVM_DEBUG(llvh::dbgs() << "Initializing a new object\n");

                                                                              
                                    
  class PropertyValue {
   public:
                                      
    bool isAccessor = false;
                                                         
    enum { None, Placeholder, IRGenerated } state{None};
                                                
    ESTree::Node *valueNode{};
                                                         
    ESTree::FunctionExpressionNode *getterNode{};
                                                         
    ESTree::FunctionExpressionNode *setterNode{};

    SMRange getSourceRange() {
      if (valueNode) {
        return valueNode->getSourceRange();
      }

      if (getterNode) {
        return getterNode->getSourceRange();
      }

      if (setterNode) {
        return setterNode->getSourceRange();
      }

      llvm_unreachable("Unset node has no location info");
    }

    void setValue(ESTree::Node *val) {
      isAccessor = false;
      valueNode = val;
      getterNode = setterNode = nullptr;
    }
    void setGetter(ESTree::FunctionExpressionNode *get) {
      if (!isAccessor) {
        valueNode = nullptr;
        setterNode = nullptr;
        isAccessor = true;
      }
      getterNode = get;
    }
    void setSetter(ESTree::FunctionExpressionNode *set) {
      if (!isAccessor) {
        valueNode = nullptr;
        getterNode = nullptr;
        isAccessor = true;
      }
      setterNode = set;
    }
  };

                                                                              
                                                                              
                    
                                                                             
                                       
  llvh::StringMap<PropertyValue> propMap;
                                                                   
  llvh::StringMap<SMRange> firstLocMap;
  llvh::SmallVector<char, 32> stringStorage;
                                      
  ESTree::PropertyNode *protoProperty = nullptr;

  uint32_t numComputed = 0;

  for (auto &P : Expr->_properties) {
    if (llvh::isa<ESTree::SpreadElementNode>(&P)) {
      continue;
    }

                                                                      
                 
    stringStorage.clear();

    auto *prop = cast<ESTree::PropertyNode>(&P);
    if (prop->_computed) {
                                                                    
                                                 
      ++numComputed;
      continue;
    }

    auto propName = propertyKeyAsString(stringStorage, prop->_key);

                                                                            
                             
    if (prop->_kind->str() == "init" && propName == "__proto__" &&
        !prop->_method && !prop->_shorthand) {
      if (!protoProperty) {
        protoProperty = prop;
      } else {
        Builder.getModule()->getContext().getSourceErrorManager().error(
            prop->getSourceRange(),
            "__proto__ was set multiple times in the object definition.");
        Builder.getModule()->getContext().getSourceErrorManager().note(
            protoProperty->getSourceRange(), "The first definition was here.");
      }
      continue;
    }

    PropertyValue *propValue = &propMap[propName];
    if (prop->_kind->str() == "get") {
      propValue->setGetter(cast<ESTree::FunctionExpressionNode>(prop->_value));
    } else if (prop->_kind->str() == "set") {
      propValue->setSetter(cast<ESTree::FunctionExpressionNode>(prop->_value));
    } else {
      assert(prop->_kind->str() == "init" && "invalid PropertyNode kind");
                                                              
      propValue->setValue(prop->_value);
    }

    std::string key = (prop->_kind->str() + propName).str();
    auto iterAndSuccess = firstLocMap.try_emplace(key, prop->getSourceRange());
    if (!iterAndSuccess.second) {
      Builder.getModule()->getContext().getSourceErrorManager().warning(
          prop->getSourceRange(),
          Twine("the property \"") + propName +
              "\" was set multiple times in the object definition.");

      Builder.getModule()->getContext().getSourceErrorManager().note(
          iterAndSuccess.first->second, "The first definition was here.");
    }
  }

                                                                       
                                                                           
                                                   
                                                                              
                                                                            
                                    
                                           
  Value *objectParent = nullptr;
  if (protoProperty &&
      (&Expr->_properties.front() == protoProperty ||
       isConstantExpr(protoProperty->_value))) {
    objectParent = genExpression(protoProperty->_value);
  }

                                                  
  auto Obj =
      Builder.createAllocObjectInst(propMap.size() + numComputed, objectParent);

                                                                               
                                                                     
                                                                             
                          
  bool haveSeenComputedProp = false;

                                                                           
                                                                              
                                                                              
                                                                            
                                                                               
                         
  for (auto &P : Expr->_properties) {
    if (auto *spread = llvh::dyn_cast<ESTree::SpreadElementNode>(&P)) {
      genBuiltinCall(
          BuiltinMethod::HermesBuiltin_copyDataProperties,
          {Obj, genExpression(spread->_argument)});
      haveSeenComputedProp = true;
      continue;
    }

                                                                      
                 
    stringStorage.clear();

    auto *prop = cast<ESTree::PropertyNode>(&P);

    if (prop->_computed) {
                                                                              
                                               
      auto *key = genExpression(prop->_key);
      auto *value = genExpression(prop->_value);
      if (prop->_kind->str() == "get") {
        Builder.createStoreGetterSetterInst(
            value,
            Builder.getLiteralUndefined(),
            Obj,
            key,
            IRBuilder::PropEnumerable::Yes);
      } else if (prop->_kind->str() == "set") {
        Builder.createStoreGetterSetterInst(
            Builder.getLiteralUndefined(),
            value,
            Obj,
            key,
            IRBuilder::PropEnumerable::Yes);
      } else {
        Builder.createStoreOwnPropertyInst(
            value, Obj, key, IRBuilder::PropEnumerable::Yes);
      }
      haveSeenComputedProp = true;
      continue;
    }

    llvh::StringRef keyStr = propertyKeyAsString(stringStorage, prop->_key);

    if (prop == protoProperty) {
                                                                         
                                                                   
                                                    
                                               
      if (!objectParent) {
        auto *parent = genExpression(prop->_value);

        IRBuilder::SaveRestore saveState{Builder};
        Builder.setLocation(prop->_key->getDebugLoc());

        genBuiltinCall(
            BuiltinMethod::HermesBuiltin_silentSetPrototypeOf, {Obj, parent});
      }

      continue;
    }

    PropertyValue *propValue = &propMap[keyStr];

                                                                              
                                                                                
                 
    auto checkState = llvh::make_scope_exit(
        [&] { assert(propValue->state != PropertyValue::None); });

    auto *Key = Builder.getLiteralString(keyStr);

    auto maybeInsertPlaceholder = [&] {
      if (propValue->state == PropertyValue::None) {
                                                                             
                                             
        if (haveSeenComputedProp) {
          Builder.createStoreOwnPropertyInst(
              Builder.getLiteralNull(),
              Obj,
              Key,
              IRBuilder::PropEnumerable::Yes);
        } else {
          Builder.createStoreNewOwnPropertyInst(
              Builder.getLiteralNull(),
              Obj,
              Key,
              IRBuilder::PropEnumerable::Yes);
        }
        propValue->state = PropertyValue::Placeholder;
      }
    };

    if (prop->_kind->str() == "get" || prop->_kind->str() == "set") {
                                           
      if (propValue->state == PropertyValue::IRGenerated)
        continue;

      if (!propValue->isAccessor) {
        maybeInsertPlaceholder();
        continue;
      }

      Value *getter = Builder.getLiteralUndefined();
      Value *setter = Builder.getLiteralUndefined();

      if (propValue->getterNode) {
        getter = genExpression(
            propValue->getterNode,
            Builder.createIdentifier("get " + keyStr.str()));
      }

      if (propValue->setterNode) {
        setter = genExpression(
            propValue->setterNode,
            Builder.createIdentifier("set " + keyStr.str()));
      }

      Builder.createStoreGetterSetterInst(
          getter, setter, Obj, Key, IRBuilder::PropEnumerable::Yes);

      propValue->state = PropertyValue::IRGenerated;

      continue;
    }

                                                                         
               
    auto value = genExpression(prop->_value, Builder.createIdentifier(keyStr));

                                                       
    if (propMap[keyStr].valueNode == prop->_value) {
      assert(
          propValue->state != PropertyValue::IRGenerated &&
          "IR can only be generated once");
      if (haveSeenComputedProp ||
          propValue->state == PropertyValue::Placeholder) {
        Builder.createStoreOwnPropertyInst(
            value, Obj, Key, IRBuilder::PropEnumerable::Yes);
      } else {
        Builder.createStoreNewOwnPropertyInst(
            value, Obj, Key, IRBuilder::PropEnumerable::Yes);
      }
      propValue->state = PropertyValue::IRGenerated;
    } else {
      maybeInsertPlaceholder();
    }
  }

                                                                            
                
  return Obj;
}

Value *ESTreeIRGen::genSequenceExpr(ESTree::SequenceExpressionNode *Sq) {
  Value *result = Builder.getLiteralUndefined();

                                                                          
  for (auto &Ex : Sq->_expressions) {
    result = genExpression(&Ex);
  }

  return result;
}

Value *ESTreeIRGen::genYieldExpr(ESTree::YieldExpressionNode *Y) {
  assert(!Y->_delegate && "must use genYieldStarExpr for yield*");

  Value *value = Y->_argument ? genExpression(Y->_argument)
                              : Builder.getLiteralUndefined();
  if (curFunction()->asyncGeneratorBody) value = genAwaitValue(value);
  return genYieldOrAwaitExpr(value);
}

Value *ESTreeIRGen::genAwaitExpr(ESTree::AwaitExpressionNode *A) {
  return genAwaitValue(genExpression(A->_argument));
}

Value *ESTreeIRGen::genAwaitValue(Value *value) {
  if (curFunction()->asyncGeneratorBody)
    value = genBuiltinCall(BuiltinMethod::HermesBuiltin_asyncGeneratorAwait, {value});
  return genYieldOrAwaitExpr(value);
}

Value *ESTreeIRGen::genYieldOrAwaitExpr(Value *value) {
  auto *bb = Builder.getInsertionBlock();
  auto *next = Builder.createBasicBlock(bb->getParent());

  auto *resumeIsReturn =
      Builder.createAllocStackInst(genAnonymousLabelName("isReturn"));

  Builder.createSaveAndYieldInst(value, next);
  Builder.setInsertionBlock(next);
  return genResumeGenerator(
      GenFinally::Yes,
      resumeIsReturn,
      Builder.createBasicBlock(bb->getParent()));
}

                                         
                                                               
                                                             
                                                        
   
                                                                   
   
                                                                    
   
                                                  
                                                              
                         
                           
   
                                                 
                                              
   
                                             
                                                                          
                                                
   
                                                                            
   
                                                                    
                                                                               
                                                                                
                                                                              
                                                  
   
                                                                          
                                                                                
                                                                               
                                                        
Value *ESTreeIRGen::genYieldStarExpr(ESTree::YieldExpressionNode *Y) {
  assert(Y->_delegate && "must use genYieldExpr for yield");
  if (curFunction()->asyncGeneratorBody)
    return genYieldOrAwaitExpr(genBuiltinCall(
        BuiltinMethod::HermesBuiltin_asyncGeneratorDelegate, {genExpression(Y->_argument)}));
  auto *function = Builder.getInsertionBlock()->getParent();
  auto *getNextBlock = Builder.createBasicBlock(function);
  auto *bodyBlock = Builder.createBasicBlock(function);
  auto *exitBlock = Builder.createBasicBlock(function);

                                                              
  auto *resumeBB = Builder.createBasicBlock(function);

  auto *exprValue = genExpression(Y->_argument);
  IteratorRecordSlow iteratorRecord = emitGetIteratorSlow(exprValue);

                                                              
                                                                          
                                      
  auto *received =
      Builder.createAllocStackInst(genAnonymousLabelName("received"));
  Builder.createStoreStackInst(Builder.getLiteralUndefined(), received);

                                                              
                                                            
  auto *resumeIsReturn =
      Builder.createAllocStackInst(genAnonymousLabelName("isReturn"));

                                                 
                                                                         
                                                       
  auto *result = Builder.createAllocStackInst(genAnonymousLabelName("result"));

  Builder.createBranchInst(getNextBlock);

                                       
                                     
                                   
                           
      
                                                                 
  Builder.setInsertionBlock(getNextBlock);
  auto *nextResult = Builder.createCallInst(
      CallInst::kNoTextifiedCallee,
      iteratorRecord.nextMethod,
      iteratorRecord.iterator,
      {Builder.createLoadStackInst(received)});
  emitEnsureObject(nextResult, "iterator.next() did not return an object");

  Builder.createStoreStackInst(nextResult, result);
  auto *done = emitIteratorCompleteSlow(nextResult);
  Builder.createCondBranchInst(done, exitBlock, bodyBlock);

  Builder.setInsertionBlock(bodyBlock);

  emitTryCatchScaffolding(
      getNextBlock,
                  
      [this,
       Y,
       resumeIsReturn,
       getNextBlock,
       resumeBB,
       nextResult,
       received,
       &iteratorRecord]() {
                                          
        SurroundingTry thisTry{
            curFunction(),
            Y,
            {},
            [this, resumeBB, received, &iteratorRecord](
                ESTree::Node *, ControlFlowChange cfc, BasicBlock *) {
              if (cfc == ControlFlowChange::Break) {
                                                                            
                                                                                
                auto *function = Builder.getFunction();
                auto *haveReturnBB = Builder.createBasicBlock(function);
                auto *noReturnBB = Builder.createBasicBlock(function);
                auto *isDoneBB = Builder.createBasicBlock(function);
                auto *isNotDoneBB = Builder.createBasicBlock(function);

                                                        
                auto *returnMethod = genBuiltinCall(
                    BuiltinMethod::HermesBuiltin_getMethod,
                    {iteratorRecord.iterator,
                     Builder.getLiteralString("return")});
                Builder.createCompareBranchInst(
                    returnMethod,
                    Builder.getLiteralUndefined(),
                    BinaryOperatorInst::OpKind::StrictlyEqualKind,
                    noReturnBB,
                    haveReturnBB);

                Builder.setInsertionBlock(haveReturnBB);
                                               
                                                                
                auto *innerReturnResult = Builder.createCallInst(
                    CallInst::kNoTextifiedCallee,
                    returnMethod,
                    iteratorRecord.iterator,
                    {Builder.createLoadStackInst(received)});
                                                                
                                               
                emitEnsureObject(
                    innerReturnResult,
                    "iterator.return() did not return an object");
                                                                          
                auto *done = emitIteratorCompleteSlow(innerReturnResult);
                Builder.createCondBranchInst(done, isDoneBB, isNotDoneBB);

                Builder.setInsertionBlock(isDoneBB);
                                                                            
                auto *value = emitIteratorValueSlow(innerReturnResult);
                genFinallyBeforeControlChange(
                    curFunction()->surroundingTry,
                    nullptr,
                    ControlFlowChange::Break);
                                             
                                                                             
                Builder.createReturnInst(value);

                                                                              
                Builder.setInsertionBlock(isNotDoneBB);
                genBuiltinCall(
                    BuiltinMethod::HermesBuiltin_generatorSetDelegated, {});
                Builder.createSaveAndYieldInst(innerReturnResult, resumeBB);

                                                                       
                Builder.setInsertionBlock(noReturnBB);
              }
            }};

                                                              
        genBuiltinCall(BuiltinMethod::HermesBuiltin_generatorSetDelegated, {});
        Builder.createSaveAndYieldInst(nextResult, resumeBB);

                                                                               
                                                                             
                                                                               
                                                                          
                                              
        Builder.setInsertionBlock(resumeBB);
        genResumeGenerator(
            GenFinally::Yes, resumeIsReturn, getNextBlock, received);

                                                                        
                                                                        
                                                
        Builder.setInsertionBlock(
            Builder.createBasicBlock(Builder.getFunction()));
      },
                           
      []() {},
                     
      [this, resumeBB, exitBlock, result, &iteratorRecord](
          BasicBlock *getNextBlock) {
        auto *catchReg = Builder.createCatchInst();

        auto *function = Builder.getFunction();
        auto *hasThrowMethodBB = Builder.createBasicBlock(function);
        auto *noThrowMethodBB = Builder.createBasicBlock(function);
        auto *isDoneBB = Builder.createBasicBlock(function);
        auto *isNotDoneBB = Builder.createBasicBlock(function);

                                                            
        auto *throwMethod = genBuiltinCall(
            BuiltinMethod::HermesBuiltin_getMethod,
            {iteratorRecord.iterator, Builder.getLiteralString("throw")});
        Builder.createCompareBranchInst(
            throwMethod,
            Builder.getLiteralUndefined(),
            BinaryOperatorInst::OpKind::StrictlyEqualKind,
            noThrowMethodBB,
            hasThrowMethodBB);

                                              
        Builder.setInsertionBlock(hasThrowMethodBB);
                                    
                                                                  
                                                                           
                                                                        
                                                
        auto *innerResult = Builder.createCallInst(
            CallInst::kNoTextifiedCallee,
            throwMethod,
            iteratorRecord.iterator,
            {catchReg});
                                                     
                                              
        emitEnsureObject(
            innerResult, "iterator.throw() did not return an object");
                                                              
        auto *throwDone = emitIteratorCompleteSlow(innerResult);
        Builder.createCondBranchInst(throwDone, isDoneBB, isNotDoneBB);

                                                                            
        Builder.setInsertionBlock(isDoneBB);
        Builder.createStoreStackInst(innerResult, result);
        Builder.createBranchInst(exitBlock);

                                                                    
        Builder.setInsertionBlock(isNotDoneBB);
        genBuiltinCall(BuiltinMethod::HermesBuiltin_generatorSetDelegated, {});
        Builder.createSaveAndYieldInst(innerResult, resumeBB);

                                                                        
                                                                        
                                         
        Builder.setInsertionBlock(noThrowMethodBB);
        emitIteratorCloseSlow(iteratorRecord, false);
        genBuiltinCall(
            BuiltinMethod::HermesBuiltin_throwTypeError,
            {Builder.getLiteralString(
                "yield* delegate must have a .throw() method")});
                                                                               
                                                                     
        Builder.createThrowInst(Builder.getLiteralUndefined());
      });

  Builder.setInsertionBlock(exitBlock);

  return emitIteratorValueSlow(Builder.createLoadStackInst(result));
}

Value *ESTreeIRGen::genResumeGenerator(
    GenFinally genFinally,
    AllocStackInst *isReturn,
    BasicBlock *nextBB,
    AllocStackInst *received) {
  auto *resume = Builder.createResumeGeneratorInst(isReturn);
  if (received) {
    Builder.createStoreStackInst(resume, received);
  }
  auto *retBB =
      Builder.createBasicBlock(Builder.getInsertionBlock()->getParent());

  Builder.createCondBranchInst(
      Builder.createLoadStackInst(isReturn), retBB, nextBB);

  Builder.setInsertionBlock(retBB);
  if (received) {
    Builder.createStoreStackInst(resume, received);
  }
  if (genFinally == GenFinally::Yes) {
    genFinallyBeforeControlChange(
        curFunction()->surroundingTry, nullptr, ControlFlowChange::Break);
  }
  Builder.createReturnInst(resume);

  Builder.setInsertionBlock(nextBB);
  return resume;
}

Value *ESTreeIRGen::genBinaryExpression(ESTree::BinaryExpressionNode *bin) {
                                               
  if (bin->_operator->str() == "+" || bin->_operator->str() == "-") {
    auto list = linearizeLeft(bin, {"+", "-"});

    Value *LHS = genExpression(list[0]->_left);
    for (auto *e : list) {
      Value *RHS = genExpression(e->_right);
      Builder.setLocation(e->getDebugLoc());
      auto cookie = instrumentIR_.preBinaryExpression(e, LHS, RHS);
      auto Kind = BinaryOperatorInst::parseOperator(e->_operator->str());
      BinaryOperatorInst *result =
          Builder.createBinaryOperatorInst(LHS, RHS, Kind);
      LHS = instrumentIR_.postBinaryExpression(e, cookie, result, LHS, RHS);
    }

    return LHS;
  }

  Value *LHS = genExpression(bin->_left);
  Value *RHS = genExpression(bin->_right);
  auto cookie = instrumentIR_.preBinaryExpression(bin, LHS, RHS);

  auto Kind = BinaryOperatorInst::parseOperator(bin->_operator->str());

  BinaryOperatorInst *result = Builder.createBinaryOperatorInst(LHS, RHS, Kind);
  return instrumentIR_.postBinaryExpression(bin, cookie, result, LHS, RHS);
}

Value *ESTreeIRGen::genUnaryExpression(ESTree::UnaryExpressionNode *U) {
  auto kind = UnaryOperatorInst::parseOperator(U->_operator->str());

                                                                       
  if (kind == UnaryOperatorInst::OpKind::DeleteKind) {
    if (auto *memberExpr =
            llvh::dyn_cast<ESTree::MemberExpressionNode>(U->_argument)) {
      LLVM_DEBUG(llvh::dbgs() << "IRGen delete member expression.\n");

      return genMemberExpression(memberExpr, MemberExpressionOperation::Delete)
          .result;
    }

    if (auto *memberExpr = llvh::dyn_cast<ESTree::OptionalMemberExpressionNode>(
            U->_argument)) {
      LLVM_DEBUG(llvh::dbgs() << "IRGen delete optional member expression.\n");

      return genOptionalMemberExpression(
                 memberExpr, nullptr, MemberExpressionOperation::Delete)
          .result;
    }

                                                                                
                                                                           
                                                                               
    if (auto *iden = llvh::dyn_cast<ESTree::IdentifierNode>(U->_argument)) {
      assert(
          !curFunction()->function->isStrictMode() &&
          "delete identifier encountered in strict mode");
                                           
      Identifier name = getNameFieldFromID(iden);
      auto *var = nameTable_.lookup(name);

      if (!var || llvh::isa<GlobalObjectProperty>(var)) {
                                                                             
                                                
        return Builder.createDeletePropertyInst(
            Builder.getGlobalObject(), Builder.getLiteralString(name));
      } else {
                                                                              
                        
        return Builder.getLiteralBool(false);
      }
    }

                                                
    genExpression(U->_argument);

                                                                    
    return Builder.getLiteralBool(true);
  }

                                                                      
  if (kind == UnaryOperatorInst::OpKind::TypeofKind) {
    if (auto *id = llvh::dyn_cast<ESTree::IdentifierNode>(U->_argument)) {
      Value *argument = genIdentifierExpression(id, true);
      return Builder.createUnaryOperatorInst(argument, kind);
    }
  }

                                
  Value *argument = genExpression(U->_argument);
  auto *cookie = instrumentIR_.preUnaryExpression(U, argument);

  Value *result;
  if (kind == UnaryOperatorInst::OpKind::PlusKind)
    result = Builder.createAsNumberInst(argument);
  else
    result = Builder.createUnaryOperatorInst(argument, kind);
  return instrumentIR_.postUnaryExpression(U, cookie, result, argument);
}

Value *ESTreeIRGen::genUpdateExpr(ESTree::UpdateExpressionNode *updateExpr) {
  LLVM_DEBUG(llvh::dbgs() << "IRGen update expression.\n");
  bool isPrefix = updateExpr->_prefix;

  UnaryOperatorInst::OpKind opKind;
  if (updateExpr->_operator->str() == "++") {
    opKind = UnaryOperatorInst::OpKind::IncKind;
  } else if (updateExpr->_operator->str() == "--") {
    opKind = UnaryOperatorInst::OpKind::DecKind;
  } else {
    llvm_unreachable("Invalid update operator");
  }

  LReference lref = createLRef(updateExpr->_argument, false);

                                                                          
                                                                         
  Value *original =
      isPrefix ? lref.emitLoad() : Builder.createAsNumericInst(lref.emitLoad());

                           
  Value *result = Builder.createUnaryOperatorInst(original, opKind);

                      
  lref.emitStore(result);

                                                                          
           
  return (isPrefix ? result : original);
}

                                          
static Identifier extractNameHint(const LReference &lref) {
  Identifier nameHint{};
  if (auto *var = lref.castAsVariable()) {
    nameHint = var->getName();
  } else if (auto *globProp = lref.castAsGlobalObjectProperty()) {
    nameHint = globProp->getName()->getValue();
  }
  return nameHint;
}

Value *ESTreeIRGen::genAssignmentExpr(ESTree::AssignmentExpressionNode *AE) {
  LLVM_DEBUG(llvh::dbgs() << "IRGen assignment operator.\n");

  auto opStr = AE->_operator->str();

                                                      
  if (opStr == "=") {
    auto list = ESTree::linearizeRight(AE, {"="});

                                                           
    llvh::SmallVector<LReference, 1> lrefs;
    lrefs.reserve(list.size());
    for (auto *e : list) {
      lrefs.push_back(createLRef(e->_left, false));
    }

    Value *RHS = nullptr;
    auto lrefIterator = lrefs.end();
    for (auto *e : llvh::make_range(list.rbegin(), list.rend())) {
      --lrefIterator;
      if (!RHS)
        RHS = genExpression(e->_right, extractNameHint(*lrefIterator));
      Builder.setLocation(e->getDebugLoc());
      auto *cookie = instrumentIR_.preAssignment(e, nullptr, RHS);
      RHS = instrumentIR_.postAssignment(e, cookie, RHS, nullptr, RHS);
      lrefIterator->emitStore(RHS);
    }

    return RHS;
  }

  auto AssignmentKind = BinaryOperatorInst::parseAssignmentOperator(opStr);

  LReference lref = createLRef(AE->_left, false);
  Identifier nameHint = extractNameHint(lref);

  Value *result;
  if (AssignmentKind == BinaryOperatorInst::OpKind::AssignShortCircuitOrKind ||
      AssignmentKind == BinaryOperatorInst::OpKind::AssignShortCircuitAndKind ||
      AssignmentKind == BinaryOperatorInst::OpKind::AssignNullishCoalesceKind) {
    return genLogicalAssignmentExpr(AE, AssignmentKind, lref, nameHint);
  }

  assert(AssignmentKind != BinaryOperatorInst::OpKind::IdentityKind);
                                                            
                                                        
                                     
                                    
  auto V = lref.emitLoad();
  auto *RHS = genExpression(AE->_right, nameHint);
  auto *cookie = instrumentIR_.preAssignment(AE, V, RHS);
  result = Builder.createBinaryOperatorInst(V, RHS, AssignmentKind);
  result = instrumentIR_.postAssignment(AE, cookie, result, V, RHS);

  lref.emitStore(result);

                                                                     
  return result;
}

Value *ESTreeIRGen::genRegExpLiteral(ESTree::RegExpLiteralNode *RE) {
  LLVM_DEBUG(llvh::dbgs() << "IRGen reg exp literal.\n");
  LLVM_DEBUG(
      llvh::dbgs() << "Loading regexp Literal \"" << RE->_pattern->str()
                   << " / " << RE->_flags->str() << "\"\n");
  auto exp = Builder.createRegExpInst(
      Identifier::getFromPointer(RE->_pattern),
      Identifier::getFromPointer(RE->_flags));

  auto &regexp = Builder.getModule()->getContext().getCompiledRegExp(
      RE->_pattern, RE->_flags);

  if (regexp.getMapping().size()) {
    auto &mapping = regexp.getMapping();
    HBCAllocObjectFromBufferInst::ObjectPropertyMap propMap;
    for (auto &identifier : regexp.getOrderedGroupNames()) {
      std::string converted;
      convertUTF16ToUTF8WithSingleSurrogates(converted, identifier);
      auto *key = Builder.getLiteralString(converted);
      auto groupIdxRes = mapping.find(identifier);
      assert(
          groupIdxRes != mapping.end() &&
          "identifier not found in named groups");
      auto groupIdx = groupIdxRes->second;
      auto *val = Builder.getLiteralNumber(groupIdx);
      propMap.emplace_back(key, val);
    }
    auto sz = mapping.size();

    auto literalObj = Builder.createHBCAllocObjectFromBufferInst(propMap, sz);

    Value *params[] = {exp, literalObj};
    Builder.createCallBuiltinInst(
        BuiltinMethod::HermesBuiltin_initRegexNamedGroups, params);
  }

  return exp;
}

Value *ESTreeIRGen::genLogicalAssignmentExpr(
    ESTree::AssignmentExpressionNode *AE,
    BinaryOperatorInst::OpKind AssignmentKind,
    LReference lref,
    Identifier nameHint) {
                                                                    
                                               
  BasicBlock *assignBB = Builder.createBasicBlock(Builder.getFunction());
                                                                 
  BasicBlock *continueBB = Builder.createBasicBlock(Builder.getFunction());
  auto *lhs = lref.emitLoad();

  PhiInst::ValueListType values;
  PhiInst::BasicBlockListType blocks;

  values.push_back(lhs);
  blocks.push_back(Builder.getInsertionBlock());

  switch (AssignmentKind) {
    case BinaryOperatorInst::OpKind::AssignShortCircuitOrKind:
      Builder.createCondBranchInst(lhs, continueBB, assignBB);
      break;
    case BinaryOperatorInst::OpKind::AssignShortCircuitAndKind:
      Builder.createCondBranchInst(lhs, assignBB, continueBB);
      break;
    case BinaryOperatorInst::OpKind::AssignNullishCoalesceKind:
      Builder.createCondBranchInst(
          Builder.createBinaryOperatorInst(
              lhs,
              Builder.getLiteralNull(),
              BinaryOperatorInst::OpKind::EqualKind),
          assignBB,
          continueBB);
      break;
    default:
      llvm_unreachable("invalid AssignmentKind in this branch");
  }

  Builder.setInsertionBlock(assignBB);
  auto *rhs = genExpression(AE->_right, nameHint);
  auto *cookie = instrumentIR_.preAssignment(AE, lhs, rhs);
  auto *result = instrumentIR_.postAssignment(AE, cookie, rhs, lhs, rhs);
  lref.emitStore(result);
  values.push_back(result);
  blocks.push_back(Builder.getInsertionBlock());
  Builder.createBranchInst(continueBB);

  Builder.setInsertionBlock(continueBB);
                                                                     
                                         
  return Builder.createPhiInst(std::move(values), std::move(blocks));
}

Value *ESTreeIRGen::genConditionalExpr(ESTree::ConditionalExpressionNode *C) {
  auto parentFunc = Builder.getInsertionBlock()->getParent();

  PhiInst::ValueListType values;
  PhiInst::BasicBlockListType blocks;

  auto alternateBlock = Builder.createBasicBlock(parentFunc);
  auto consequentBlock = Builder.createBasicBlock(parentFunc);
  auto continueBlock = Builder.createBasicBlock(parentFunc);

                                                                           
                                                        
  genExpressionBranch(C->_test, consequentBlock, alternateBlock, nullptr);

                     
  Builder.setInsertionBlock(consequentBlock);

  values.push_back(genExpression(C->_consequent));
  blocks.push_back(Builder.getInsertionBlock());
  Builder.createBranchInst(continueBlock);

                     
  Builder.setInsertionBlock(alternateBlock);
  values.push_back(genExpression(C->_alternate));
  blocks.push_back(Builder.getInsertionBlock());
  Builder.createBranchInst(continueBlock);

              
  Builder.setInsertionBlock(continueBlock);
  return Builder.createPhiInst(values, blocks);
}

Value *ESTreeIRGen::genIdentifierExpression(
    ESTree::IdentifierNode *Iden,
    bool afterTypeOf) {
  LLVM_DEBUG(
      llvh::dbgs() << "Looking for identifier \"" << Iden->_name << "\"\n");

                                                                        
                                                                       
                       
  if (Iden->_name->str() == "arguments" &&
      !nameTable_.count(getNameFieldFromID(Iden))) {
                                                         
    if (curFunction()->capturedArguments) {
      return Builder.createLoadFrameInst(
          curFunction()->capturedArguments, currentIRScope_);
    }

    return curFunction()->createArgumentsInst;
  }

                          
  auto StrName = getNameFieldFromID(Iden);

  auto *Var = ensureVariableExists(Iden);

                                                                          
                                         
  if (llvh::isa<GlobalObjectProperty>(Var) && StrName.str() == "undefined") {
    return Builder.getLiteralUndefined();
  }

  LLVM_DEBUG(
      llvh::dbgs() << "Found variable " << StrName << " in function \""
                   << (llvh::isa<GlobalObjectProperty>(Var)
                           ? llvh::StringRef("global")
                           : cast<Variable>(Var)
                                 ->getParent()
                                 ->getFunction()
                                 ->getInternalNameStr())
                   << "\"\n");

                                      
  return emitLoad(Var, afterTypeOf);
}

Value *ESTreeIRGen::genMetaProperty(ESTree::MetaPropertyNode *MP) {
                           
  if (cast<ESTree::IdentifierNode>(MP->_meta)->_name->str() == "new") {
    if (cast<ESTree::IdentifierNode>(MP->_property)->_name->str() == "target") {
      Value *value;

      if (curFunction()->function->getDefinitionKind() ==
              Function::DefinitionKind::ES6Arrow ||
          curFunction()->function->getDefinitionKind() ==
              Function::DefinitionKind::ES6Method) {
        value = curFunction()->capturedNewTarget;
      } else {
        value = Builder.createGetNewTargetInst();
      }

                                                   
      if (auto *V = llvh::dyn_cast<Variable>(value))
        return Builder.createLoadFrameInst(V, currentIRScope_);

      return value;
    }
  }

  llvm_unreachable("invalid MetaProperty");
}

Value *ESTreeIRGen::genNewExpr(ESTree::NewExpressionNode *N) {
  LLVM_DEBUG(llvh::dbgs() << "IRGen 'new' statement/expression.\n");

  Value *callee = genExpression(N->_callee);

  bool hasSpread = false;
  for (auto &arg : N->_arguments) {
    if (llvh::isa<ESTree::SpreadElementNode>(&arg)) {
      hasSpread = true;
    }
  }

  if (!hasSpread) {
    ConstructInst::ArgumentList args;
    for (auto &arg : N->_arguments) {
      args.push_back(genExpression(&arg));
    }

    return Builder.createConstructInst(callee, callee, args);
  }

                                                                          
                 
                                                                         
                                                  
  auto *args = genArrayFromElements(N->_arguments);

  return genBuiltinCall(BuiltinMethod::HermesBuiltin_apply, {callee, args});
}

Value *ESTreeIRGen::genLogicalExpression(
    ESTree::LogicalExpressionNode *logical) {
  auto opStr = logical->_operator->str();
  LLVM_DEBUG(llvh::dbgs() << "IRGen of short circuiting: " << opStr << ".\n");

  enum class Kind {
    And,      
    Or,      
    Coalesce,      
  };

  Kind kind;

  if (opStr == "&&") {
    kind = Kind::And;
  } else if (opStr == "||") {
    kind = Kind::Or;
  } else if (opStr == "??") {
    kind = Kind::Coalesce;
  } else {
    llvm_unreachable("Invalid update operator");
  }

                                               
  auto tempVarName = genAnonymousLabelName("logical");
  auto parentFunc = Builder.getInsertionBlock()->getParent();
  auto tempVar = Builder.createAllocStackInst(tempVarName);

  auto evalRHSBlock = Builder.createBasicBlock(parentFunc);
  auto continueBlock = Builder.createBasicBlock(parentFunc);

  auto LHS = genExpression(logical->_left);

                                                                               
                                                                            
                                                  
  Builder.createStoreStackInst(LHS, tempVar);

                                                                              
            
  switch (kind) {
    case Kind::And:
                                                
      Builder.createCondBranchInst(LHS, evalRHSBlock, continueBlock);
      break;
    case Kind::Or:
                                                 
      Builder.createCondBranchInst(LHS, continueBlock, evalRHSBlock);
      break;
    case Kind::Coalesce:
                                                             
                                                                  
      Builder.createCondBranchInst(
          Builder.createBinaryOperatorInst(
              LHS,
              Builder.getLiteralNull(),
              BinaryOperatorInst::OpKind::EqualKind),
          evalRHSBlock,
          continueBlock);

      break;
  }

                                                                      
  Builder.setInsertionBlock(evalRHSBlock);
  auto RHS = genExpression(logical->_right);

                                                                       
  Builder.createStoreStackInst(RHS, tempVar);

                                             
  Builder.createBranchInst(continueBlock);

                                                                               
  Builder.setInsertionBlock(continueBlock);
  return Builder.createLoadStackInst(tempVar);
}

void ESTreeIRGen::genLogicalExpressionBranch(
    ESTree::LogicalExpressionNode *logical,
    BasicBlock *onTrue,
    BasicBlock *onFalse,
    BasicBlock *onNullish) {
  auto opStr = logical->_operator->str();
  LLVM_DEBUG(
      llvh::dbgs() << "IRGen of short circuiting: " << opStr << " branch.\n");

  auto parentFunc = Builder.getInsertionBlock()->getParent();
  auto *block = Builder.createBasicBlock(parentFunc);

  if (opStr == "&&") {
    genExpressionBranch(logical->_left, block, onFalse, onNullish);
  } else if (opStr == "||") {
    genExpressionBranch(logical->_left, onTrue, block, onNullish);
  } else {
    assert(opStr == "??" && "invalid logical operator");
    genExpressionBranch(logical->_left, onTrue, onFalse, block);
  }

  Builder.setInsertionBlock(block);
  genExpressionBranch(logical->_right, onTrue, onFalse, onNullish);
}

Value *ESTreeIRGen::genTemplateLiteralExpr(ESTree::TemplateLiteralNode *Expr) {
  LLVM_DEBUG(llvh::dbgs() << "IRGen 'TemplateLiteral' expression.\n");

  assert(
      Expr->_quasis.size() == Expr->_expressions.size() + 1 &&
      "The string count should always be one more than substitution count.");

                                                                    
                                                                               
                                                                            
                                               

                                 
  auto strItr = Expr->_quasis.begin();
  auto *tempEltNode = cast<ESTree::TemplateElementNode>(&*strItr);
  auto *firstCookedStr = Builder.getLiteralString(tempEltNode->_cooked->str());
  ++strItr;
                                                                                
  if (strItr == Expr->_quasis.end()) {
    return firstCookedStr;
  }
  CallInst::ArgumentList argList;
  auto exprItr = Expr->_expressions.begin();
  while (strItr != Expr->_quasis.end()) {
    auto *sub = genExpression(&*exprItr);
    argList.push_back(sub);
    tempEltNode = cast<ESTree::TemplateElementNode>(&*strItr);
    auto cookedStr = tempEltNode->_cooked->str();
    if (!cookedStr.empty()) {
      argList.push_back(Builder.getLiteralString(cookedStr));
    }
    ++strItr;
    ++exprItr;
  }
  assert(
      exprItr == Expr->_expressions.end() &&
      "All the substitutions must have been collected.");

                                                                              
  return genHermesInternalCall("concat", firstCookedStr, argList);
}

Value *ESTreeIRGen::genTaggedTemplateExpr(
    ESTree::TaggedTemplateExpressionNode *Expr) {
  LLVM_DEBUG(llvh::dbgs() << "IRGen 'TaggedTemplateExpression' expression.\n");
                                     
  auto *templateLit = cast<ESTree::TemplateLiteralNode>(Expr->_quasi);

                                                                               
                                                                       
  CallInst::ArgumentList argList;
                                 
  Module::RawStringList rawStrings;
  for (auto &n : templateLit->_quasis) {
    auto element = cast<ESTree::TemplateElementNode>(&n);
    rawStrings.push_back(Builder.getLiteralString(element->_raw->str()));
  }
  uint32_t templateObjID = Mod->getTemplateObjectID(std::move(rawStrings));
  argList.push_back(Builder.getLiteralNumber(templateObjID));

                                                                      
  bool dup = true;
                                                                        
                             
  argList.push_back(Builder.getLiteralBool(dup));
  for (auto &node : templateLit->_quasis) {
    auto *templateElt = cast<ESTree::TemplateElementNode>(&node);
    if (templateElt->_cooked != templateElt->_raw) {
      dup = false;
    }
    argList.push_back(Builder.getLiteralString(templateElt->_raw->str()));
  }
  argList[1] = Builder.getLiteralBool(dup);
                                                                          
                   
  if (!dup) {
    for (auto &node : templateLit->_quasis) {
      auto *templateElt = cast<ESTree::TemplateElementNode>(&node);
      if (templateElt->_cooked) {
        argList.push_back(
            Builder.getLiteralString(templateElt->_cooked->str()));
      } else {
        argList.push_back(Builder.getLiteralUndefined());
      }
    }
  }

                                                                              
               
  auto *templateObj =
      genBuiltinCall(BuiltinMethod::HermesBuiltin_getTemplateObject, argList);

                                                                             
                                        
  CallInst::ArgumentList tagFuncArgList;
  tagFuncArgList.push_back(templateObj);
  for (auto &sub : templateLit->_expressions) {
    tagFuncArgList.push_back(genExpression(&sub));
  }

  Value *callee;
  Value *thisVal;
                                         
  if (auto *Mem = llvh::dyn_cast<ESTree::MemberExpressionNode>(Expr->_tag)) {
    Value *obj = genExpression(Mem->_object);
    Value *prop = genMemberExpressionProperty(Mem);
                                              
    thisVal = obj;
    callee = Builder.createLoadPropertyInst(obj, prop);
  } else {
    thisVal = Builder.getLiteralUndefined();
    callee = genExpression(Expr->_tag);
  }

  return Builder.createCallInst(
      CallInst::kNoTextifiedCallee, callee, thisVal, tagFuncArgList);
}

}                   
}                    
