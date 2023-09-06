/*
	Author: Lousix
	Version: 2.0
*/

import java
import semmle.code.java.dataflow.FlowSources
private import semmle.code.java.dataflow.ExternalFlow
import SpringRelated.SpringController // 此处注意import的文件路径

from  Class c, Method m
where 
	m = c.getAMethod() 
select
    c as controller, m as method,
    getControllerRoute(c, m) as route,
	// getContentType(m),
	getRequestMethod(m)
