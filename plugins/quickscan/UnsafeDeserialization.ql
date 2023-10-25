/**
 * @name Deserialization of user-controlled data
 * @description Deserializing user-controlled data may allow attackers to
 *              execute arbitrary code.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id java/unsafe-deserialization
 * @tags security
 *       external/cwe/cwe-502
 */

import java
import semmle.code.java.security.UnsafeDeserializationQuery
import UnsafeDeserializationFlow::PathGraph
private import semmle.code.java.dataflow.ExternalFlow
import SpringRelated.SpringController
import SpringRelated.SpringParam


from UnsafeDeserializationFlow::PathNode source, UnsafeDeserializationFlow::PathNode sink, Class c, Method m
where UnsafeDeserializationFlow::flowPath(source, sink)
and
m = c.getAMethod() 
and
getControllerFunc(source.getNode().getEnclosingCallable()) = m
select c, m, source, sink, "UnsafeDeserialization.ql", sink.getNode().(UnsafeDeserializationSink).getMethodAccess(),
  "Unsafe deserialization depends on a $@.", source.getNode(), "user-provided value"
