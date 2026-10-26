/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

                                
                                                         
                                                                           
C_STRING((function() {
  var colors = {};
                                                                 
  var HermesPromise = globalThis.Promise;

  function populateColors() {
    colors.red = '\033[31m';
    colors.green = '\033[32m';
    colors.yellow = '\033[33m';
    colors.blue = '\033[34m';
    colors.magenta = '\033[35m';
    colors.cyan = '\033[36m';
    colors.white = '\033[37m';

    colors.reset = '\033[0m';
  }

  function clearColors() {
    colors.red = "";
    colors.green = "";
    colors.yellow = "";
    colors.blue = "";
    colors.magenta = "";
    colors.cyan = "";
    colors.white = "";

    colors.reset = "";
  }

  function prettyPrintProp(value, prop, visited) {
    var desc = Object.getOwnPropertyDescriptor(value, prop);
    var result = "";
    if (desc.enumerable) {
      result += String(prop) + ': ';
    } else {
      result += '[' + String(prop) + ']: ';
    }
    if (desc.get || desc.set) {
      result += colors.cyan + '[accessor]' + colors.reset;
    } else {
      result += prettyPrintRec(desc.value, visited);
    }
    return result;
  }

  function prettyPrintNumber(value) {
    if (Object.is(-0, value)) {
      return "-0";
    }
    return String(value);
  }

  function prettyPrintPromise(value, visited) {
    var internalColor = colors.cyan;
    var internals = "";
    switch(value['_i']) {
      case 0:
        internals = "<pending>";
        break;
      case 1:
        internals = "<fulfilled: " + colors.reset +
            prettyPrintRec(value['_j'], visited) +
            internalColor + ">";
        break;
      case 2:
        internals = "<rejected: " + colors.reset +
            prettyPrintRec(value['_j'], visited) +
            internalColor + ">";
        break;
      case 3:
                                                                               
        return prettyPrintPromise(value['_j'], visited);
      default:
        break;
    };
    var internalString = internalColor + internals + colors.reset;

    var elements = [];
    var propNames = Object.getOwnPropertyNames(value);
    var internalNames = ['_h', '_i', '_j', '_k'];
    for (var i = 0; i < propNames.length; ++i) {
      var prop = propNames[i];
                                  
      if (!internalNames.includes(prop)) {
        elements.push(prettyPrintProp(value, prop, visited));
      }
    }
    var elementString =
        elements.length === 0 ? "" : " { " + elements.join(', ') +  " }";
    return "Promise " + internalString + elementString;
  }

  function prettyPrintRec(value, visited) {
                               
    if (visited.has(value)) {
      return colors.magenta + '[cyclic]' + colors.reset;
    }

    switch (typeof value) {
      case "undefined":
        return colors.white + "undefined" + colors.reset;
      case "number":
        return colors.yellow + prettyPrintNumber(value) + colors.reset;
      case "bigint":
        return colors.yellow + value + "n" + colors.reset;
      case "string":
                                                   
        return colors.green + '"' + value + '"' + colors.reset;
      case "symbol":
        return colors.green + String(value) + colors.reset;
      case "boolean":
        return colors.yellow + String(value) + colors.reset;
      case "function":
                                                                             
        var functionColor = colors.cyan;
        if (visited.size === 0) {
          return functionColor + String(value) + colors.reset;
        }
        if (!value.name) {
          return functionColor + '[Function]' + colors.reset;
        }
        return functionColor + '[Function ' + value.name + ']' + colors.reset;
    }

    if (value === null) {
      return colors.white + 'null' + colors.reset;
    }

                                                               
    visited.add(value);

    if (Array.isArray(value)) {
                                           
      var length = value.length;
      var elements = [];
      var numEmpty = 0;
      for (var i = 0; i < length; ++i) {
                                                                  
        if (!value.hasOwnProperty(i)) {
                                                  
          ++numEmpty;
        } else {
          if (numEmpty > 0) {
            elements.push(
              colors.white + numEmpty + ' x <empty>' + colors.reset);
          }
          numEmpty = 0;
          if (value.propertyIsEnumerable(i)) {
            elements.push(prettyPrintRec(value[i], visited));
          } else {
            elements.push(
              '[' + String(i) + ']: ' + prettyPrintRec(value[i], visited));
          }
        }
      }
      if (numEmpty > 0) {
        elements.push(
          colors.white + numEmpty + ' x <empty>' + colors.reset);
      }
      var propNames = Object.getOwnPropertyNames(value);
      for (var i = 0; i < propNames.length; ++i) {
                                                                
        var prop = propNames[i];
        if (isNaN(Number(prop))) {
          elements.push(prettyPrintProp(value, prop, visited));
        }
      }
      return '[ ' + elements.join(', ') + ' ]';
    }

    if (value instanceof RegExp) {
      return colors.green + value.toString() + colors.reset;
    }

    if (value instanceof Set) {
      var elementStrings = [];
      value.forEach(function(element) {
        elementStrings.push(prettyPrintRec(element, visited));
      });
      return "Set { " + elementStrings.join(", ") + " }";
    }

    if (value instanceof Map) {
      var elementStrings = [];
      value.forEach(function(v, k) {
        elementStrings.push(
          prettyPrintRec(k, visited) + " => " + prettyPrintRec(v, visited)
        );
      });
      return "Map { " + elementStrings.join(", ") + " }";
    }

    if (value instanceof Date) {
      var isValid = !isNaN(value.getTime());
      return colors.cyan + "[Date " +
        (isValid ? value.toISOString() : "Invalid") +
        "]" + colors.reset;
    }

    function isTypedArray(val) {
      return val instanceof Int8Array ||
             val instanceof Int16Array ||
             val instanceof Int32Array ||
             val instanceof Uint8Array ||
             val instanceof Uint16Array ||
             val instanceof Uint32Array ||
             val instanceof Float32Array ||
             val instanceof Float64Array ||
             val instanceof BigInt64Array ||
             val instanceof BigUint64Array;
    }

    if (isTypedArray(value)) {
      var elementStrings = [];
      value.forEach(function(i) {
        elementStrings.push(prettyPrintRec(i, visited));
      });
      return value.constructor.name + " [ " + elementStrings.join(", ") + " ]";
    }

    function isPromise(val) {
                                                                                
      return HermesInternal.hasPromise() && value instanceof HermesPromise;
    }

    if (isPromise(value)) {
      return prettyPrintPromise(value, visited);
    }

                                                                      
    var elements = [];
    var propNames = Object.getOwnPropertyNames(value);
    for (var i = 0; i < propNames.length; ++i) {
      var prop = propNames[i];
      elements.push(prettyPrintProp(value, prop, visited));
    }
    if (Object.getOwnPropertySymbols) {
      var propSymbols = Object.getOwnPropertySymbols(value);
      for (var i = 0; i < propSymbols.length; ++i) {
        var prop = propSymbols[i];
        elements.push(prettyPrintProp(value, prop, visited));
      }
    }
    if (value.constructor && value.constructor.name && value.constructor.name !== "Object") {
      return value.constructor.name + ' { ' + elements.join(', ') + ' }';
    } else if (value[Symbol.toStringTag]) {
                                                                                  
                                                                                          
                                                                                         
      return value[Symbol.toStringTag] + ' { ' + elements.join(', ') + ' }';
    } else {
      return '{ ' + elements.join(', ') + ' }';
    }
  }

  function prettyPrint(value, isColored) {
    isColored ? populateColors() : clearColors();
    return prettyPrintRec(value, new Set());
  }

  var singleCommentPattern = new RegExp("^//");
  var multiCommentPattern = new RegExp("^/\\*.*\\*/$");

                                                
                                                    
                                                            
  function evaluateLine(input, isColored) {
    var output;
    var trimmed = input.trim();
    if (trimmed.length === 0) {
                                      
      return undefined;
    }
    if (singleCommentPattern.test(trimmed) ||
        multiCommentPattern.test(trimmed)) {
                                                        
      return undefined;
    }
                                                                 
                       
    if (trimmed[0] === '{' && trimmed[trimmed.length - 1] === '}') {
      try {
                                                                             
        output = (1, eval)('(' + input + ')');
      } catch (e) {
                                                                        
        output = (1, eval)(input);
      }
    } else {
                                                                 
      output = (1, eval)(input);
    }

                                         
    return prettyPrint(output, isColored);
  }

  return evaluateLine;
})())
