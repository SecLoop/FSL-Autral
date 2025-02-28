/**
 * @name Local-user-controlled data in path expression
 * @description Accessing paths influenced by users can allow an attacker to access unexpected resources.
 * @kind path-problem
 * @problem.severity recommendation
 * @security-severity 7.5
 * @precision medium
 * @id java/path-injection-local
 * @tags security
 *       external/cwe/cwe-022
 *       external/cwe/cwe-023
 *       external/cwe/cwe-036
 *       external/cwe/cwe-073
 */

import java
import semmle.code.java.security.PathCreation
import semmle.code.java.security.TaintedPathQuery
import TaintedPathLocalFlow::PathGraph
private import semmle.code.java.dataflow.ExternalFlow
import SpringRelated.SpringController
import SpringRelated.SpringParam

/**
 * Gets the data-flow node at which to report a path ending at `sink`.
 *
 * Previously this query flagged alerts exclusively at `PathCreation` sites,
 * so to avoid perturbing existing alerts, where a `PathCreation` exists we
 * continue to report there; otherwise we report directly at `sink`.
 */
DataFlow::Node getReportingNode(DataFlow::Node sink) {
  TaintedPathLocalFlow::flowTo(sink) and
  if exists(PathCreation pc | pc.getAnInput() = sink.asExpr())
  then result.asExpr() = any(PathCreation pc | pc.getAnInput() = sink.asExpr())
  else result = sink
}

from TaintedPathLocalFlow::PathNode source, TaintedPathLocalFlow::PathNode sink, Class c, Method m
where TaintedPathLocalFlow::flowPath(source, sink)
and
m = c.getAMethod() 
and
getControllerFunc(source.getNode().getEnclosingCallable()) = m
select  c, m, source, sink, "TaintedPathLocal.ql", getParam(source.getNode()), getReportingNode(sink.getNode()), "This path depends on a $@.",
  source.getNode(), "user-provided value"
