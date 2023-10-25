/*
	Author: Lousix
	Version: 2.0
	Description: 提取 
*/

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources
import SpringController

/*
	以 source 为搜索点递归反查调用点，
	通过是否存在注解（@XXXMapping）判断是否为 spring 输入
*/
predicate isControllerFunc(Callable callable) {
	isTargetMethod(callable)
	or 
	isControllerFunc(callable.getAReference().getCaller())
}

/*
	与上同理
	返回参数为 用户输入Controller的Callable
*/
Callable getControllerFunc(Callable callable) {
	if 
	isTargetMethod(callable)
	then 
	result = callable
	else
	result = getControllerFunc(callable.getAReference().getCaller())
}

/*
	处理 source 的值
	 1）带有注解  提取value √
	 2）带有注解  无Value 提取参数名 √
	 2）无注解    参数名 	√
	 3）request  参数
	 4）RequestBody		  √
 */

string getParam(DataFlow::Node source){
	// RequestBody
	(
		source.asParameter().hasAnnotation()
		and
		source.asParameter().getAnAnnotation().getType().hasQualifiedName(
			"org.springframework.web.bind.annotation","RequestBody"
		)
		and
		result = "POST Data"
	)
	or
	// 带有注解  提取value
	(
		source.asParameter().hasAnnotation()
		and
		source.asParameter().getAnAnnotation().getValue("value").toString() != "\"\""
		and
		result = source.asParameter().getAnAnnotation().getValue("value").toString()
	)
	or
	// 无注解    参数名 
	(
		not source.asParameter().hasAnnotation()
		and
		result = source.asParameter().toString()
	)
	or
	// 带有注解  无value 提取参数名
	(
		source.asParameter().hasAnnotation()
		and
		source.asParameter().getAnAnnotation().getValue("value").toString() = "\"\""
		and
		result = source.asParameter().toString()
	)
	or
	(
		result = source.asExpr().(MethodAccess).getAnArgument().toString()
	)
	or
	(
		count(source.asExpr().getAChildExpr()) = 1
		and
		result = source.toString()
	)
}

/*
	有注解的，提取注解类型
	没注解的，返回no AnAnnotation
 */
string getParamAnnotation(DataFlow::Node source){
	(
		source.asParameter().hasAnnotation()
		and
		result = source.asParameter().getAnAnnotation().toString()
	)
	or
	(
		not source.asParameter().hasAnnotation()
		and
		result = "no AnAnnotation"
	)
}

string getRequestType(DataFlow::Node source){
	(
		source.toString().matches("get%")
		and
		result = source.toString()
	)
	or
	(
		not source.toString().matches("get%")
		and 
		result = ""
	)
}


// string sourceToString(DataFlow::Node source) {
// 	if 
// 	source.asExpr().getAChildExpr()
// 	then 
// 	result = "111"
// }

/*
	查询demo
*/
// from DataFlow::Node source
// where source instanceof RemoteFlowSource 
// 	and 
// 	getControllerFunc(source.getEnclosingCallable())
// select source

    // getControllerParam(m) as params