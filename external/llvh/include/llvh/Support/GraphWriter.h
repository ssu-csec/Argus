//===- llvm/Support/GraphWriter.h - Write graph to a .dot file --*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines a simple interface that can be used to print out generic
// LLVM graphs to ".dot" files.  "dot" is a tool that is part of the AT&T
// graphviz package (http://www.research.att.com/sw/tools/graphviz/) which can
// be used to turn the files output by this interface into a variety of
// different graphics formats.
//
// Graphs do not need to implement any interface past what is already required
// by the GraphTraits template, but they can choose to implement specializations
// of the DOTGraphTraits template if they want to customize the graphs output in
// any way.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_GRAPHWRITER_H
#define LLVM_SUPPORT_GRAPHWRITER_H

#include "llvh/ADT/GraphTraits.h"
#include "llvh/ADT/StringRef.h"
#include "llvh/ADT/Twine.h"
#include "llvh/Support/DOTGraphTraits.h"
#include "llvh/Support/FileSystem.h"
#include "llvh/Support/raw_ostream.h"
#include <algorithm>
#include <cstddef>
#include <iterator>
#include <string>
#include <type_traits>
#include <vector>

namespace llvh {

namespace DOT {                         

std::string EscapeString(const std::string &Label);

                                                                       
                                       
StringRef getColorString(unsigned NodeNumber);

}                     

namespace GraphProgram {

enum Name {
  DOT,
  FDP,
  NEATO,
  TWOPI,
  CIRCO
};

}                              

bool DisplayGraph(StringRef Filename, bool wait = true,
                  GraphProgram::Name program = GraphProgram::DOT);

template<typename GraphType>
class GraphWriter {
  raw_ostream &O;
  const GraphType &G;

  using DOTTraits = DOTGraphTraits<GraphType>;
  using GTraits = GraphTraits<GraphType>;
  using NodeRef = typename GTraits::NodeRef;
  using node_iterator = typename GTraits::nodes_iterator;
  using child_iterator = typename GTraits::ChildIteratorType;
  DOTTraits DTraits;

  static_assert(std::is_pointer<NodeRef>::value,
                "FIXME: Currently GraphWriter requires the NodeRef type to be "
                "a pointer.\nThe pointer usage should be moved to "
                "DOTGraphTraits, and removed from GraphWriter itself.");

                                                                              
                                                  
  bool getEdgeSourceLabels(raw_ostream &O, NodeRef Node) {
    child_iterator EI = GTraits::child_begin(Node);
    child_iterator EE = GTraits::child_end(Node);
    bool hasEdgeSourceLabels = false;

    for (unsigned i = 0; EI != EE && i != 64; ++EI, ++i) {
      std::string label = DTraits.getEdgeSourceLabel(Node, EI);

      if (label.empty())
        continue;

      hasEdgeSourceLabels = true;

      if (i)
        O << "|";

      O << "<s" << i << ">" << DOT::EscapeString(label);
    }

    if (EI != EE && hasEdgeSourceLabels)
      O << "|<s64>truncated...";

    return hasEdgeSourceLabels;
  }

public:
  GraphWriter(raw_ostream &o, const GraphType &g, bool SN) : O(o), G(g) {
    DTraits = DOTTraits(SN);
  }

  void writeGraph(const std::string &Title = "") {
                                         
    writeHeader(Title);

                                            
    writeNodes();

                                             
    DOTGraphTraits<GraphType>::addCustomGraphFeatures(G, *this);

                                  
    writeFooter();
  }

  void writeHeader(const std::string &Title) {
    std::string GraphName = DTraits.getGraphName(G);

    if (!Title.empty())
      O << "digraph \"" << DOT::EscapeString(Title) << "\" {\n";
    else if (!GraphName.empty())
      O << "digraph \"" << DOT::EscapeString(GraphName) << "\" {\n";
    else
      O << "digraph unnamed {\n";

    if (DTraits.renderGraphFromBottomUp())
      O << "\trankdir=\"BT\";\n";

    if (!Title.empty())
      O << "\tlabel=\"" << DOT::EscapeString(Title) << "\";\n";
    else if (!GraphName.empty())
      O << "\tlabel=\"" << DOT::EscapeString(GraphName) << "\";\n";
    O << DTraits.getGraphProperties(G);
    O << "\n";
  }

  void writeFooter() {
                           
    O << "}\n";
  }

  void writeNodes() {
                                              
    for (const auto Node : nodes<GraphType>(G))
      if (!isNodeHidden(Node))
        writeNode(Node);
  }

  bool isNodeHidden(NodeRef Node) {
    return DTraits.isNodeHidden(Node);
  }

  void writeNode(NodeRef Node) {
    std::string NodeAttributes = DTraits.getNodeAttributes(Node, G);

    O << "\tNode" << static_cast<const void*>(Node) << " [shape=record,";
    if (!NodeAttributes.empty()) O << NodeAttributes << ",";
    O << "label=\"{";

    if (!DTraits.renderGraphFromBottomUp()) {
      O << DOT::EscapeString(DTraits.getNodeLabel(Node, G));

                                                                              
      std::string Id = DTraits.getNodeIdentifierLabel(Node, G);
      if (!Id.empty())
        O << "|" << DOT::EscapeString(Id);

      std::string NodeDesc = DTraits.getNodeDescription(Node, G);
      if (!NodeDesc.empty())
        O << "|" << DOT::EscapeString(NodeDesc);
    }

    std::string edgeSourceLabels;
    raw_string_ostream EdgeSourceLabels(edgeSourceLabels);
    bool hasEdgeSourceLabels = getEdgeSourceLabels(EdgeSourceLabels, Node);

    if (hasEdgeSourceLabels) {
      if (!DTraits.renderGraphFromBottomUp()) O << "|";

      O << "{" << EdgeSourceLabels.str() << "}";

      if (DTraits.renderGraphFromBottomUp()) O << "|";
    }

    if (DTraits.renderGraphFromBottomUp()) {
      O << DOT::EscapeString(DTraits.getNodeLabel(Node, G));

                                                                              
      std::string Id = DTraits.getNodeIdentifierLabel(Node, G);
      if (!Id.empty())
        O << "|" << DOT::EscapeString(Id);

      std::string NodeDesc = DTraits.getNodeDescription(Node, G);
      if (!NodeDesc.empty())
        O << "|" << DOT::EscapeString(NodeDesc);
    }

    if (DTraits.hasEdgeDestLabels()) {
      O << "|{";

      unsigned i = 0, e = DTraits.numEdgeDestLabels(Node);
      for (; i != e && i != 64; ++i) {
        if (i) O << "|";
        O << "<d" << i << ">"
          << DOT::EscapeString(DTraits.getEdgeDestLabel(Node, i));
      }

      if (i != e)
        O << "|<d64>truncated...";
      O << "}";
    }

    O << "}\"];\n";                                     

                                  
    child_iterator EI = GTraits::child_begin(Node);
    child_iterator EE = GTraits::child_end(Node);
    for (unsigned i = 0; EI != EE && i != 64; ++EI, ++i)
      if (!DTraits.isNodeHidden(*EI))
        writeEdge(Node, i, EI);
    for (; EI != EE; ++EI)
      if (!DTraits.isNodeHidden(*EI))
        writeEdge(Node, 64, EI);
  }

  void writeEdge(NodeRef Node, unsigned edgeidx, child_iterator EI) {
    if (NodeRef TargetNode = *EI) {
      int DestPort = -1;
      if (DTraits.edgeTargetsEdgeSource(Node, EI)) {
        child_iterator TargetIt = DTraits.getEdgeTarget(Node, EI);

                                                
        unsigned Offset =
          (unsigned)std::distance(GTraits::child_begin(TargetNode), TargetIt);
        DestPort = static_cast<int>(Offset);
      }

      if (DTraits.getEdgeSourceLabel(Node, EI).empty())
        edgeidx = -1;

      emitEdge(static_cast<const void*>(Node), edgeidx,
               static_cast<const void*>(TargetNode), DestPort,
               DTraits.getEdgeAttributes(Node, EI, G));
    }
  }

                                                         
  void emitSimpleNode(const void *ID, const std::string &Attr,
                   const std::string &Label, unsigned NumEdgeSources = 0,
                   const std::vector<std::string> *EdgeSourceLabels = nullptr) {
    O << "\tNode" << ID << "[ ";
    if (!Attr.empty())
      O << Attr << ",";
    O << " label =\"";
    if (NumEdgeSources) O << "{";
    O << DOT::EscapeString(Label);
    if (NumEdgeSources) {
      O << "|{";

      for (unsigned i = 0; i != NumEdgeSources; ++i) {
        if (i) O << "|";
        O << "<s" << i << ">";
        if (EdgeSourceLabels) O << DOT::EscapeString((*EdgeSourceLabels)[i]);
      }
      O << "}}";
    }
    O << "\"];\n";
  }

                                                                    
  void emitEdge(const void *SrcNodeID, int SrcNodePort,
                const void *DestNodeID, int DestNodePort,
                const std::string &Attrs) {
    if (SrcNodePort  > 64) return;                                              
    if (DestNodePort > 64) DestNodePort = 64;                                  

    O << "\tNode" << SrcNodeID;
    if (SrcNodePort >= 0)
      O << ":s" << SrcNodePort;
    O << " -> Node" << DestNodeID;
    if (DestNodePort >= 0 && DTraits.hasEdgeDestLabels())
      O << ":d" << DestNodePort;

    if (!Attrs.empty())
      O << "[" << Attrs << "]";
    O << ";\n";
  }

                                                                           
                                                        
  raw_ostream &getOStream() {
    return O;
  }
};

template<typename GraphType>
raw_ostream &WriteGraph(raw_ostream &O, const GraphType &G,
                        bool ShortNames = false,
                        const Twine &Title = "") {
                                        
  GraphWriter<GraphType> W(O, G, ShortNames);

                    
  W.writeGraph(Title.str());

  return O;
}

std::string createGraphFilename(const Twine &Name, int &FD);

                                                  
                                                         
                                                                 
           
template <typename GraphType>
std::string WriteGraph(const GraphType &G, const Twine &Name,
                       bool ShortNames = false,
                       const Twine &Title = "",
                       std::string Filename = "") {
  int FD;
                                                                             
  std::string N = Name.str();
  N = N.substr(0, std::min<std::size_t>(N.size(), 140));
  if (Filename.empty()) {
    Filename = createGraphFilename(N, FD);
  } else {
    std::error_code EC = sys::fs::openFileForWrite(Filename, FD);

                                                                
    if (EC == std::errc::file_exists) {
      errs() << "file exists, overwriting" << "\n";
    } else if (EC) {
      errs() << "error writing into file" << "\n";
      return "";
    }
  }
  raw_fd_ostream O(FD,                  true);

  if (FD == -1) {
    errs() << "error opening file '" << Filename << "' for writing!\n";
    return "";
  }

  llvh::WriteGraph(O, G, ShortNames, Title);
  errs() << " done. \n";

  return Filename;
}

                                                                           
                                             
   
template<typename GraphType>
void ViewGraph(const GraphType &G, const Twine &Name,
               bool ShortNames = false, const Twine &Title = "",
               GraphProgram::Name Program = GraphProgram::DOT) {
  std::string Filename = llvh::WriteGraph(G, Name, ShortNames, Title);

  if (Filename.empty())
    return;

  DisplayGraph(Filename, false, Program);
}

}                      

#endif                              
