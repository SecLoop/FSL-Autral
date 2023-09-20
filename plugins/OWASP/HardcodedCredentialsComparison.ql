/**
 * @name Hard-coded credential comparison
 * @description Comparing a parameter to a hard-coded credential may compromise security.
 * @kind problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision low
 * @id java/hardcoded-credential-comparison
 * @tags security
 *       external/cwe/cwe-798
 */

import java
import semmle.code.java.security.HardcodedCredentialsComparison
private import semmle.code.java.dataflow.ExternalFlow
import SpringRelated.SpringController
import SpringRelated.SpringParam

from EqualsAccess sink, HardcodedExpr source, PasswordVariable p, Class c, Method m
where isHardcodedCredentialsComparison(sink, source, p)
and
m = c.getAMethod() 
and
getControllerFunc(source.getNode().getEnclosingCallable()) = m
select c,m,source,sink, "HardcodedCredentialsComparison.ql", "Hard-coded value is $@ with password variable $@.", sink, "compared", p, p.getName()
