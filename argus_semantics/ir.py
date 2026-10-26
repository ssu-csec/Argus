"""Parser for Hermes 0.12 textual high-level IR, with explicit CFG/value IDs."""
from dataclasses import dataclass, field
import ast
import re

def split_operands(text):
    out=[];start=0;quote=None;escape=False;depth=0
    for i,c in enumerate(text):
        if quote:
            if escape:escape=False
            elif c=='\\':escape=True
            elif c==quote:quote=None
        elif c in '\"\'':quote=c
        elif c in '[{(':depth+=1
        elif c in ']})':depth-=1
        elif c==',' and depth==0:out.append(text[start:i].strip());start=i+1
    if text[start:].strip():out.append(text[start:].strip())
    return out

def untype(s):
    if s.startswith(('"',"'")):
        q=s[0];escape=False
        for i,c in enumerate(s[1:],1):
            if escape:escape=False
            elif c=='\\':escape=True
            elif c==q:return s[:i+1]
    return s.split(' : ')[0].strip()

def literal(s):
    s=untype(s)
    if s.startswith(('"',"'")):
        try:return ast.literal_eval(s)
        except (ValueError,SyntaxError):return None
    return None


                                                                      
HEADER_KINDS=('derived constructor','async generator','constructor','generator','function','method','arrow')
def split_header(header):
    for kind in HEADER_KINDS:
        if header.startswith(kind+' '):return kind,header[len(kind)+1:]
    raise ValueError('Unsupported IR function header')

def header_body(header):return split_header(header)[1]

def function_name(body):
    if body.startswith('"'):return literal(body)
                                                                                  
    name=re.sub(r'\([^()]*\)#\d+(?: : .*)?$', '', body)
    return re.sub(r'(?:#\d+)+$', '', name)

@dataclass
class Inst:
    id: str
    op: str
    args: list
    block: str
    loc: tuple | None
    text: str

@dataclass
class Function:
    header: str
    name: str
    insts: dict = field(default_factory=dict)
    blocks: dict = field(default_factory=dict)
    preds: dict = field(default_factory=dict)
    succ: dict = field(default_factory=dict)
    positions: dict = field(default_factory=dict)
    live_blocks: set = field(default_factory=set)
    local_slots: set = field(default_factory=set)
    scope_slots: dict = field(default_factory=dict)

    def finish(self):
        for b,items in self.blocks.items():
            for pos,i in enumerate(items): self.positions[i.id]=pos
            last=items[-1] if items else None
                                                                              
                                                                                
            self.succ[b]=[untype(x) for x in last.args if untype(x).startswith('%BB')] if last else []
        self.preds={b:[] for b in self.blocks}
        for b,targets in self.succ.items():
            for t in targets:self.preds.setdefault(t,[]).append(b)
        todo=list(self.blocks)[:1]
        while todo:
            b=todo.pop()
            if b in self.live_blocks:continue
            self.live_blocks.add(b);todo.extend(self.succ.get(b,[]))
        self.preds={b:[p for p in ps if p in self.live_blocks] for b,ps in self.preds.items()}

    def reachable(self,start,target):
        todo=[start];seen=set()
        while todo:
            b=todo.pop()
            if b==target:return True
            if b in seen:continue
            seen.add(b);todo.extend(self.succ.get(b,[]))
        return False

class Program(list):
    complete=False
    creation_index=None

def parse(text,complete=False):
    functions=Program();functions.complete=complete;f=None;bb=None;loc=None;seen_headers=set();functions.coverage_errors=[]
    prefixes=tuple(k+' ' for k in HEADER_KINDS)
    for line in text.split('\n'):
        if line.startswith(prefixes):
            if f is not None:functions.coverage_errors.append('NESTED_OR_UNTERMINATED')
            rest=header_body(line);name=function_name(rest)
            if complete and line in seen_headers:raise ValueError('Duplicate IR function identity')
            seen_headers.add(line)
            f=Function(line,name);functions.append(f);loc=None;bb=None
        elif f:
            if line.startswith('S{') and ' = [' in line:
                                                                                        
                                                                                 
                scope,body=line.split(' = [',1)
                slots={'['+x+']' for x in split_operands(body.rstrip(']'))}
                f.local_slots.update(slots)
                                                                            
                f.scope_slots[scope]=None if scope in f.scope_slots else slots
            m=re.match(r'; .*:(\d+):(\d+)\s*$',line)
            if m:loc=tuple(map(int,m.groups()))
            if line.startswith('%BB'):
                bb=line.strip().rstrip(':');f.blocks.setdefault(bb,[])
            m=re.match(r'\s*(%\d+) = (\w+)\s*(.*)',line)
            if m and bb:
                i=Inst(m[1],m[2],split_operands(m[3]),bb,loc,line.strip())
                f.insts[i.id]=i;f.blocks[bb].append(i)
            if line.startswith('function_end'):f.finish();f=None
        elif line.startswith('function_end'):functions.coverage_errors.append('UNMATCHED_END')
    if f is not None:functions.coverage_errors.append('UNTERMINATED')
    return functions
