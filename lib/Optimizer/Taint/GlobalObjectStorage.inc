                                                                                
                                                                            
                                                                               
                                                                               
                                                                               
namespace {
struct GlobalObjectStorageIndex {
  std::unordered_map<LoadPropertyInst *, StorePropertyInst *> edges;
  unsigned scanned=0, barriers=0;
  bool admitted=false, limited=false;
  void build(Module *m) {
    if(!reachingStoreGlobalContract(m))return;
    const std::unordered_set<std::string> roots={"window","self","globalThis"};
    for(auto *b:m->getGlobalProperties())
      if(b->isDeclared()&&roots.count(reachingStoreLiteralName(b->getName())))return;
                                                                           
                                                                              
    for(Function &f:*m)for(BasicBlock &b:f)for(Instruction &i:b) {
      if(++scanned>250000){limited=true;return;}
      Value *key=nullptr;
      if(auto *s=llvh::dyn_cast<StorePropertyInst>(&i))key=s->getProperty();
      if(auto *s=llvh::dyn_cast<StoreOwnPropertyInst>(&i))key=s->getProperty();
      if(auto *s=llvh::dyn_cast<DeletePropertyInst>(&i))key=s->getProperty();
      if(key&&roots.count(reachingStoreLiteralName(key)))return;
    }
    admitted=true;
    for(Function &f:*m)for(BasicBlock &b:f) {
      std::unordered_map<Value *,std::string> objects;
      std::map<std::pair<Value *,Variable *>,std::string> frames;
      std::map<std::pair<std::string,std::string>,StorePropertyInst *> cells;
      auto object=[&](Value *v){auto it=objects.find(v);return it==objects.end()?std::string():it->second;};
      auto barrier=[&](){cells.clear();++barriers;};
      for(Instruction &i:b) {
        if(auto *s=llvh::dyn_cast<StoreFrameInst>(&i)) {
          auto env=reachingStoreBindingEnvironment(s->getEnvironment(),s->getVariable());
          frames[{env,s->getVariable()}]=object(s->getValue());continue;
        }
        if(auto *l=llvh::dyn_cast<LoadFrameInst>(&i)) {
          auto env=reachingStoreBindingEnvironment(l->getEnvironment(),l->getLoadVariable());
          auto it=frames.find({env,l->getLoadVariable()});if(it!=frames.end())objects[l]=it->second;continue;
        }
        if(auto *v=llvh::dyn_cast<MovInst>(&i)){objects[v]=object(v->getOperand(0));continue;}
        if(auto *v=llvh::dyn_cast<ThrowIfEmptyInst>(&i)) {
                                                                             
                                                                           
          auto obj=object(v->getOperand(0));
          if(!obj.empty()){objects[v]=obj;continue;}
        }
        if(auto *l=llvh::dyn_cast<LoadPropertyInst>(&i)) {
          auto key=reachingStoreLiteralName(l->getProperty());
          if(l->getObject()==m->getGlobalObject()&&roots.count(key)){objects[l]=key;continue;}
          if(reachingStoreSafeGlobalRead(l,m)||reachingStoreTrustedNowRead(l,m))continue;
          auto obj=object(l->getObject());
          if(!obj.empty()&&!key.empty()){
            auto it=cells.find({obj,key});if(it!=cells.end()){edges[l]=it->second;continue;}
          }
                                                                                
          barrier();continue;
        }
        if(auto *s=llvh::dyn_cast<StorePropertyInst>(&i)) {
          auto obj=object(s->getObject()),key=reachingStoreLiteralName(s->getProperty());
          if(!obj.empty()&&!key.empty()){cells[{obj,key}]=s;continue;}
          barrier();continue;
        }
        if(auto *c=llvh::dyn_cast<CallInst>(&i)) {
          if(reachingStoreTrustedNowCall(c,m))continue;
          barrier();frames.clear();objects.clear();continue;
        }
        if(i.mayExecute()){barrier();frames.clear();objects.clear();}
      }
    }
  }
};
thread_local GlobalObjectStorageIndex globalObjectStorage;
thread_local unsigned globalObjectStorageSeeds=0;
}             
