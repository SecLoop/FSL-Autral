/**
 * @name User-controlled data used in permissions check
 * @description Using user-controlled data in a permissions check may result in inappropriate
 *              permissions being granted.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.8
 * @precision high
 * @id java/tainted-permissions-check
 * @tags security
 *       external/cwe/cwe-807
 *       external/cwe/cwe-290
 */

import java
import semmle.code.java.security.TaintedPermissionsCheckQuery
import TaintedPermissionsCheckFlow::PathGraph
private import semmle.code.java.dataflow.ExternalFlow
import SpringRelated.SpringController
import SpringRelated.SpringParam

from
  TaintedPermissionsCheckFlow::PathNode source, TaintedPermissionsCheckFlow::PathNode sink,
  PermissionsConstruction p, Class c, Method m
where sink.getNode().asExpr() = p.getInput() and TaintedPermissionsCheckFlow::flowPath(source, sink)
and
m = c.getAMethod() 
and
getControllerFunc(source.getNode().getEnclosingCallable()) = m
select c, m, source, sink, "TaintedPermissionsCheck.ql", getParam(source), p, "Permissions check depends on a $@.", source.getNode(),
  "user-controlled value"
