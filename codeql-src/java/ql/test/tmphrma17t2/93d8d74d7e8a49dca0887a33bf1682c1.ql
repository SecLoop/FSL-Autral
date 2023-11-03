/**
 * @name Insecure Bean Validation
 * @description User-controlled data may be evaluated as a Java EL expression, leading to arbitrary code execution.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.3
 * @precision high
 * @id java/insecure-bean-validation
 * @tags security
 *       external/cwe/cwe-094
 */

import java
import semmle.code.java.security.InsecureBeanValidationQuery
import BeanValidationFlow::PathGraph
private import semmle.code.java.dataflow.ExternalFlow
import SpringRelated.SpringController
import SpringRelated.SpringParam

from BeanValidationFlow::PathNode source, BeanValidationFlow::PathNode sink, Class c, Method m
where
  (
    not exists(SetMessageInterpolatorCall call)
    or
    exists(SetMessageInterpolatorCall call | not c.isSafe())
  ) and
  BeanValidationFlow::flowPath(source, sink)
  and
  m = c.getAMethod() 
  and
  getControllerFunc(source.getNode().getEnclosingCallable()) = m
select c, m, source, sink, "InsecureBeanValidation.ql", getParam(source), "Custom constraint error message contains an unsanitized $@.",
  source, "user-provided value", sink.getNode()
